// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include <errno.h>
#include <string.h>

#include "common/ceph_crypto.h"
#include "common/Formatter.h"
#include "common/utf8.h"
#include "common/ceph_json.h"

#include "rgw_rest.h"
#include "rgw_rest_s3.h"
#include "rgw_auth_s3.h"
#include "rgw_policy_s3.h"
#include "rgw_user.h"
#include "rgw_cors.h"
#include "rgw_cors_s3.h"

#include "rgw_client_io.h"
#define dout_subsys ceph_subsys_rgw

using namespace ceph::crypto;

string dss_endpoint::endpoint = " ";

void list_all_buckets_start(struct req_state *s)
{
  s->formatter->open_array_section_in_ns("ListAllMyBucketsResult",
                                         (dss_endpoint::endpoint).c_str());
}

void list_all_buckets_end(struct req_state *s)
{
  s->formatter->close_section();
}

void dump_bucket(struct req_state *s, RGWBucketEnt& obj)
{
  s->formatter->open_object_section("Bucket");
  s->formatter->dump_string("Name", obj.bucket.name);
  dump_time(s, "CreationDate", &obj.creation_time);
  s->formatter->close_section();
}

void rgw_get_errno_s3(rgw_http_errors *e , int err_no)
{
  const struct rgw_http_errors *r;
  r = search_err(err_no, RGW_HTTP_ERRORS, ARRAY_LEN(RGW_HTTP_ERRORS));

  if (r) {
    e->http_ret = r->http_ret;
    e->s3_code = r->s3_code;
  } else {
    e->http_ret = 500;
    e->s3_code = "UnknownError";
  }
}

struct response_attr_param {
  const char *param;
  const char *http_attr;
};

static struct response_attr_param resp_attr_params[] = {
  {"response-content-type", "Content-Type"},
  {"response-content-language", "Content-Language"},
  {"response-expires", "Expires"},
  {"response-cache-control", "Cache-Control"},
  {"response-content-disposition", "Content-Disposition"},
  {"response-content-encoding", "Content-Encoding"},
  {NULL, NULL},
};

int RGWGetObj_ObjStore_S3::send_response_data(bufferlist& bl, off_t bl_ofs, off_t bl_len)
{
  const char *content_type = NULL;
  string content_type_str;
  map<string, string> response_attrs;
  map<string, string>::iterator riter;
  bufferlist metadata_bl;

  if (ret)
    goto done;

  if (sent_header)
    goto send_data;

  if (range_str)
    dump_range(s, start, end, s->obj_size);

  if (s->system_request &&
      s->info.args.exists(RGW_SYS_PARAM_PREFIX "prepend-metadata")) {

    /* JSON encode object metadata */
    JSONFormatter jf;
    jf.open_object_section("obj_metadata");
    encode_json("attrs", attrs, &jf);
    encode_json("mtime", lastmod, &jf);
    jf.close_section();
    stringstream ss;
    jf.flush(ss);
    metadata_bl.append(ss.str());
    s->cio->print("Rgwx-Embedded-Metadata-Len: %lld\r\n", (long long)metadata_bl.length());
    total_len += metadata_bl.length();
  }

  if (s->system_request && lastmod) {
    /* we end up dumping mtime in two different methods, a bit redundant */
    dump_epoch_header(s, "Rgwx-Mtime", lastmod);
  }

  dump_content_length(s, total_len);
  dump_last_modified(s, lastmod);

  if (!ret) {
    map<string, bufferlist>::iterator iter = attrs.find(RGW_ATTR_ETAG);
    if (iter != attrs.end()) {
      bufferlist& bl = iter->second;
      if (bl.length()) {
        char *etag = bl.c_str();
        dump_etag(s, etag);
      }
    }

    for (struct response_attr_param *p = resp_attr_params; p->param; p++) {
      bool exists;
      string val = s->info.args.get(p->param, &exists);
      if (exists) {
	if (strcmp(p->param, "response-content-type") != 0) {
	  response_attrs[p->http_attr] = val;
	} else {
	  content_type_str = val;
	  content_type = content_type_str.c_str();
	}
      }
    }

    for (iter = attrs.begin(); iter != attrs.end(); ++iter) {
      const char *name = iter->first.c_str();
      map<string, string>::iterator aiter = rgw_to_http_attrs.find(name);
      if (aiter != rgw_to_http_attrs.end()) {
	if (response_attrs.count(aiter->second) > 0) // was already overridden by a response param
	  continue;

	if (aiter->first.compare(RGW_ATTR_CONTENT_TYPE) == 0) { // special handling for content_type
	  if (!content_type)
	    content_type = iter->second.c_str();
	  continue;
        }
	response_attrs[aiter->second] = iter->second.c_str();
      } else {
        if (strncmp(name, RGW_ATTR_META_PREFIX, sizeof(RGW_ATTR_META_PREFIX)-1) == 0) {
          name += sizeof(RGW_ATTR_PREFIX) - 1;
          s->cio->print("%s: %s\r\n", name, iter->second.c_str());
        }
      }
    }
  }

done:
  set_req_state_err(s, (partial_content && !ret) ? STATUS_PARTIAL_CONTENT : ret);

  dump_errno(s);

  for (riter = response_attrs.begin(); riter != response_attrs.end(); ++riter) {
    s->cio->print("%s: %s\r\n", riter->first.c_str(), riter->second.c_str());
  }

  if (!content_type)
    content_type = "binary/octet-stream";

  end_header(s, this, content_type);

  if (metadata_bl.length()) {
    s->cio->write(metadata_bl.c_str(), metadata_bl.length());
  }
  sent_header = true;

send_data:
  if (get_data && !ret) {
    int r = s->cio->write(bl.c_str() + bl_ofs, bl_len);
    if (r < 0)
      return r;
  }

  return 0;
}

void RGWListBuckets_ObjStore_S3::send_response_begin(bool has_buckets)
{
  if (ret)
    set_req_state_err(s, ret);
  dump_errno(s);
  dump_start(s);
  end_header(s, NULL, "application/xml");

  if (!ret) {
    list_all_buckets_start(s);
    dump_owner(s, s->user.user_id, s->user.display_name);
    s->formatter->open_array_section("Buckets");
    sent_data = true;
  }
}

void RGWListBuckets_ObjStore_S3::send_response_data(RGWUserBuckets& buckets)
{
  if (!sent_data)
    return;

  map<string, RGWBucketEnt>& m = buckets.get_buckets();
  map<string, RGWBucketEnt>::iterator iter;

  for (iter = m.begin(); iter != m.end(); ++iter) {
    RGWBucketEnt obj = iter->second;
    dump_bucket(s, obj);
  }
  rgw_flush_formatter(s, s->formatter);
}

void RGWListBuckets_ObjStore_S3::send_response_end()
{
  if (sent_data) {
    s->formatter->close_section();
    list_all_buckets_end(s);
    rgw_flush_formatter_and_reset(s, s->formatter);
  }
}

int RGWListBucket_ObjStore_S3::get_params()
{
  list_versions = s->info.args.exists("versions");
  prefix = s->info.args.get("prefix");
  if (!list_versions) {
    marker = s->info.args.get("marker");
  } else {
    marker.name = s->info.args.get("key-marker");
    marker.instance = s->info.args.get("version-id-marker");
  }
  max_keys = s->info.args.get("max-keys");
  ret = parse_max_keys();
  if (ret < 0) {
    return ret;
  }
  delimiter = s->info.args.get("delimiter");
  encoding_type = s->info.args.get("encoding-type");
  return 0;
}

void RGWListBucket_ObjStore_S3::send_versioned_response()
{
  s->formatter->open_object_section_in_ns("ListVersionsResult",
					  (dss_endpoint::endpoint).c_str());
  s->formatter->dump_string("Name", s->bucket_name_str);
  s->formatter->dump_string("Prefix", prefix);
  s->formatter->dump_string("KeyMarker", marker.name);
  if (is_truncated && !next_marker.empty())
    s->formatter->dump_string("NextKeyMarker", next_marker.name);
  s->formatter->dump_int("MaxKeys", max);
  if (!delimiter.empty())
    s->formatter->dump_string("Delimiter", delimiter);

  s->formatter->dump_string("IsTruncated", (max && is_truncated ? "true" : "false"));

  bool encode_key = false;
  if (strcasecmp(encoding_type.c_str(), "url") == 0)
    encode_key = true;

  if (ret >= 0) {
    vector<RGWObjEnt>::iterator iter;
    for (iter = objs.begin(); iter != objs.end(); ++iter) {
      time_t mtime = iter->mtime.sec();
      const char *section_name = (iter->is_delete_marker() ? "DeleteMarker" : "Version");
      s->formatter->open_array_section(section_name);
      if (encode_key) {
        string key_name;
        url_encode(iter->key.name, key_name);
        s->formatter->dump_string("Key", key_name);
      } else {
        s->formatter->dump_string("Key", iter->key.name);
      }
      string version_id = iter->key.instance;
      if (version_id.empty()) {
        version_id = "null";
      }
      if (s->system_request && iter->versioned_epoch > 0) {
        s->formatter->dump_int("VersionedEpoch", iter->versioned_epoch);
      }
      s->formatter->dump_string("VersionId", version_id);
      s->formatter->dump_bool("IsLatest", iter->is_current());
      dump_time(s, "LastModified", &mtime);
      if (!iter->is_delete_marker()) {
        s->formatter->dump_format("ETag", "\"%s\"", iter->etag.c_str());
        s->formatter->dump_int("Size", iter->size);
        s->formatter->dump_string("StorageClass", "STANDARD");
      }
      dump_owner(s, iter->owner, iter->owner_display_name);
      s->formatter->close_section();
    }
    if (!common_prefixes.empty()) {
      map<string, bool>::iterator pref_iter;
      for (pref_iter = common_prefixes.begin(); pref_iter != common_prefixes.end(); ++pref_iter) {
        s->formatter->open_array_section("CommonPrefixes");
        s->formatter->dump_string("Prefix", pref_iter->first);
        s->formatter->close_section();
      }
    }
  }
  s->formatter->close_section();
  rgw_flush_formatter_and_reset(s, s->formatter);
}

void RGWListBucket_ObjStore_S3::send_response()
{
  if (ret < 0)
    set_req_state_err(s, ret);
  dump_errno(s);

  end_header(s, this, "application/xml");
  dump_start(s);
  if (ret < 0)
    return;

  if (list_versions) {
    send_versioned_response();
    return;
  }

  s->formatter->open_object_section_in_ns("ListBucketResult",
					  (dss_endpoint::endpoint).c_str());
  s->formatter->dump_string("Name", s->bucket_name_str);
  s->formatter->dump_string("Prefix", prefix);
  s->formatter->dump_string("Marker", marker.name);
  if (is_truncated && !next_marker.empty())
    s->formatter->dump_string("NextMarker", next_marker.name);
  s->formatter->dump_int("MaxKeys", max);
  if (!delimiter.empty())
    s->formatter->dump_string("Delimiter", delimiter);

  s->formatter->dump_string("IsTruncated", (max && is_truncated ? "true" : "false"));

  bool encode_key = false;
  if (strcasecmp(encoding_type.c_str(), "url") == 0)
    encode_key = true;

  if (ret >= 0) {
    vector<RGWObjEnt>::iterator iter;
    for (iter = objs.begin(); iter != objs.end(); ++iter) {
      s->formatter->open_array_section("Contents");
      if (encode_key) {
        string key_name;
        url_encode(iter->key.name, key_name);
        s->formatter->dump_string("Key", key_name);
      } else {
        s->formatter->dump_string("Key", iter->key.name);
      }
      time_t mtime = iter->mtime.sec();
      dump_time(s, "LastModified", &mtime);
      s->formatter->dump_format("ETag", "\"%s\"", iter->etag.c_str());
      s->formatter->dump_int("Size", iter->size);
      s->formatter->dump_string("StorageClass", "STANDARD");
      dump_owner(s, iter->owner, iter->owner_display_name);
      s->formatter->close_section();
    }
    if (!common_prefixes.empty()) {
      map<string, bool>::iterator pref_iter;
      for (pref_iter = common_prefixes.begin(); pref_iter != common_prefixes.end(); ++pref_iter) {
        s->formatter->open_array_section("CommonPrefixes");
        s->formatter->dump_string("Prefix", pref_iter->first);
        s->formatter->close_section();
      }
    }
  }
  s->formatter->close_section();
  rgw_flush_formatter_and_reset(s, s->formatter);
}

void RGWGetBucketLogging_ObjStore_S3::send_response()
{
  dump_errno(s);
  end_header(s, this, "application/xml");
  dump_start(s);

  s->formatter->open_object_section_in_ns("BucketLoggingStatus",
					  (dss_endpoint::endpoint).c_str());
  s->formatter->close_section();
  rgw_flush_formatter_and_reset(s, s->formatter);
}

void RGWGetBucketLocation_ObjStore_S3::send_response()
{
  dump_errno(s);
  end_header(s, this);
  dump_start(s);

  string region = s->bucket_info.region;
  string api_name;

  map<string, RGWRegion>::iterator iter = store->region_map.regions.find(region);
  if (iter != store->region_map.regions.end()) {
    api_name = iter->second.api_name;
  } else  {
    if (region != "default") {
      api_name = region;
    }
  }

  s->formatter->dump_format_ns("LocationConstraint",
			       (dss_endpoint::endpoint).c_str(),
			       "%s",api_name.c_str());
  rgw_flush_formatter_and_reset(s, s->formatter);
}

void RGWGetBucketVersioning_ObjStore_S3::send_response()
{
  dump_errno(s);
  end_header(s, this, "application/xml");
  dump_start(s);

  s->formatter->open_object_section_in_ns("VersioningConfiguration",
					  (dss_endpoint::endpoint).c_str());
  if (versioned) {
    const char *status = (versioning_enabled ? "Enabled" : "Suspended");
    s->formatter->dump_string("Status", status);
  }
  s->formatter->close_section();
  rgw_flush_formatter_and_reset(s, s->formatter);
}

class RGWSetBucketVersioningParser : public RGWXMLParser
{
  XMLObj *alloc_obj(const char *el) {
    return new XMLObj;
  }

public:
  RGWSetBucketVersioningParser() {}
  ~RGWSetBucketVersioningParser() {}

  int get_versioning_status(bool *status) {
    XMLObj *config = find_first("VersioningConfiguration");
    if (!config)
      return -EINVAL;

    *status = false;

    XMLObj *field = config->find_first("Status");
    if (!field)
      return 0;

    string& s = field->get_data();

    if (stringcasecmp(s, "Enabled") == 0) {
      *status = true;
    } else if (stringcasecmp(s, "Suspended") != 0) {
      return -EINVAL;
    }

    return 0;
  }
};

int RGWSetBucketVersioning_ObjStore_S3::get_params()
{
#define GET_BUCKET_VERSIONING_BUF_MAX (128 * 1024)

  char *data;
  int len = 0;
  int r = rgw_rest_read_all_input(s, &data, &len, GET_BUCKET_VERSIONING_BUF_MAX);
  if (r < 0) {
    return r;
  }

  RGWSetBucketVersioningParser parser;

  if (!parser.init()) {
    ldout(s->cct, 0) << "ERROR: failed to initialize parser" << dendl;
    r = -EIO;
    goto done;
  }

  if (!parser.parse(data, len, 1)) {
    ldout(s->cct, 10) << "failed to parse data: " << data << dendl;
    r = -EINVAL;
    goto done;
  }

  r = parser.get_versioning_status(&enable_versioning);

done:
  free(data);

  return r;
}

void RGWSetBucketVersioning_ObjStore_S3::send_response()
{
  if (ret)
    set_req_state_err(s, ret);
  dump_errno(s);
  end_header(s);
}


static void dump_bucket_metadata(struct req_state *s, RGWBucketEnt& bucket)
{
  char buf[32];
  snprintf(buf, sizeof(buf), "%lld", (long long)bucket.count);
  s->cio->print("x-jcs-Object-Count: %s\r\n", buf); //<<<<<< X-RGW-
  snprintf(buf, sizeof(buf), "%lld", (long long)bucket.size);
  s->cio->print("x-jcs-Bytes-Used: %s\r\n", buf);
}

void RGWStatBucket_ObjStore_S3::send_response()
{
  if (ret >= 0) {
    dump_bucket_metadata(s, bucket);
  }

  set_req_state_err(s, ret);
  dump_errno(s);

  end_header(s, this);
  dump_start(s);
}

static int create_s3_policy(struct req_state *s, RGWRados *store, RGWAccessControlPolicy_S3& s3policy, ACLOwner& owner)
{
  if (s->has_acl_header) {
    if (!s->canned_acl.empty())
      return -ERR_INVALID_REQUEST;

    return s3policy.create_from_headers(store, s->info.env, owner);
  }

  return s3policy.create_canned(owner, s->bucket_owner, s->canned_acl);
}

class RGWLocationConstraint : public XMLObj
{
public:
  RGWLocationConstraint() {}
  ~RGWLocationConstraint() {}
  bool xml_end(const char *el) {
    if (!el)
      return false;

    location_constraint = get_data();

    return true;
  }

  string location_constraint;
};

class RGWCreateBucketConfig : public XMLObj
{
public:
  RGWCreateBucketConfig() {}
  ~RGWCreateBucketConfig() {}
};

class RGWCreateBucketParser : public RGWXMLParser
{
  XMLObj *alloc_obj(const char *el) {
    return new XMLObj;
  }

public:
  RGWCreateBucketParser() {}
  ~RGWCreateBucketParser() {}

  bool get_location_constraint(string& region) {
    XMLObj *config = find_first("CreateBucketConfiguration");
    if (!config)
      return false;

    XMLObj *constraint = config->find_first("LocationConstraint");
    if (!constraint)
      return false;

    region = constraint->get_data();

    return true;
  }
};

int RGWCreateBucket_ObjStore_S3::get_params()
{
  RGWAccessControlPolicy_S3 s3policy(s->cct);

  int r = create_s3_policy(s, store, s3policy, s->owner);
  if (r < 0)
    return r;

  policy = s3policy;

  int len = 0;
  char *data;
#define CREATE_BUCKET_MAX_REQ_LEN (512 * 1024) /* this is way more than enough */
  ret = rgw_rest_read_all_input(s, &data, &len, CREATE_BUCKET_MAX_REQ_LEN);
  if ((ret < 0) && (ret != -ERR_LENGTH_REQUIRED))
    return ret;

  bufferptr in_ptr(data, len);
  in_data.append(in_ptr);

  if (len) {
    RGWCreateBucketParser parser;

    if (!parser.init()) {
      ldout(s->cct, 0) << "ERROR: failed to initialize parser" << dendl;
      return -EIO;
    }

    bool success = parser.parse(data, len, 1);
    ldout(s->cct, 20) << "create bucket input data=" << data << dendl;

    if (!success) {
      ldout(s->cct, 0) << "failed to parse input: " << data << dendl;
      free(data);
      return -EINVAL;
    }
    free(data);

    if (!parser.get_location_constraint(location_constraint)) {
      ldout(s->cct, 0) << "provided input did not specify location constraint correctly" << dendl;
      return -EINVAL;
    }

    ldout(s->cct, 10) << "create bucket location constraint: " << location_constraint << dendl;
  }

  int pos = location_constraint.find(':');
  if (pos >= 0) {
    placement_rule = location_constraint.substr(pos + 1);
    location_constraint = location_constraint.substr(0, pos);
  }

  return 0;
}

void RGWCreateBucket_ObjStore_S3::send_response()
{
  if (ret == -ERR_BUCKET_EXISTS)
    ret = 0;
  if (ret)
    set_req_state_err(s, ret);
  dump_errno(s);
  end_header(s);

  if (ret < 0)
    return;

  if (s->system_request) {
    JSONFormatter f; /* use json formatter for system requests output */

    f.open_object_section("info");
    encode_json("entry_point_object_ver", ep_objv, &f);
    encode_json("object_ver", info.objv_tracker.read_version, &f);
    encode_json("bucket_info", info, &f);
    f.close_section();
    rgw_flush_formatter_and_reset(s, &f);
  }
}

void RGWDeleteBucket_ObjStore_S3::send_response()
{
  int r = ret;
  if (!r)
    r = STATUS_NO_CONTENT;

  set_req_state_err(s, r);
  dump_errno(s);
  end_header(s, this);

  if (s->system_request) {
    JSONFormatter f; /* use json formatter for system requests output */

    f.open_object_section("info");
    encode_json("object_ver", objv_tracker.read_version, &f);
    f.close_section();
    rgw_flush_formatter_and_reset(s, &f);
  }
}

int RGWPutObj_ObjStore_S3::get_params()
{
  RGWAccessControlPolicy_S3 s3policy(s->cct);
  if (!s->length)
    return -ERR_LENGTH_REQUIRED;

  int r = create_s3_policy(s, store, s3policy, s->owner);
  if (r < 0)
    return r;

  policy = s3policy;

  if_match = s->info.env->get("HTTP_IF_MATCH");
  if_nomatch = s->info.env->get("HTTP_IF_NONE_MATCH");

  return RGWPutObj_ObjStore::get_params();
}

static int get_success_retcode(int code)
{
  switch (code) {
    case 201:
      return STATUS_CREATED;
    case 204:
      return STATUS_NO_CONTENT;
  }
  return 0;
}

void RGWPutObj_ObjStore_S3::send_response()
{
  if (ret) {
    set_req_state_err(s, ret);
  } else {
    if (s->cct->_conf->rgw_s3_success_create_obj_status) {
      ret = get_success_retcode(s->cct->_conf->rgw_s3_success_create_obj_status);
      set_req_state_err(s, ret);
    }
    dump_etag(s, etag.c_str());
    dump_content_length(s, 0);
  }
  if (s->system_request && mtime) {
    dump_epoch_header(s, "Rgwx-Mtime", mtime);
  }
  dump_errno(s);
  end_header(s, this);
}

/*
 * parses params in the format: 'first; param1=foo; param2=bar'
 */
static void parse_params(const string& params_str, string& first, map<string, string>& params)
{
  int pos = params_str.find(';');
  if (pos < 0) {
    first = rgw_trim_whitespace(params_str);
    return;
  }

  first = rgw_trim_whitespace(params_str.substr(0, pos));

  pos++;

  while (pos < (int)params_str.size()) {
    ssize_t end = params_str.find(';', pos);
    if (end < 0)
      end = params_str.size();

    string param = params_str.substr(pos, end - pos);

    int eqpos = param.find('=');
    if (eqpos > 0) {
      string param_name = rgw_trim_whitespace(param.substr(0, eqpos));
      string val = rgw_trim_quotes(param.substr(eqpos + 1));
      params[param_name] = val;
    } else {
      params[rgw_trim_whitespace(param)] = "";
    }

    pos = end + 1;
  }
}

static int parse_part_field(const string& line, string& field_name, struct post_part_field& field)
{
  int pos = line.find(':');
  if (pos < 0)
    return -EINVAL;

  field_name = line.substr(0, pos);
  if (pos >= (int)line.size() - 1)
    return 0;

  parse_params(line.substr(pos + 1), field.val, field.params);

  return 0;
}

bool is_crlf(const char *s)
{
  return (*s == '\r' && *(s + 1) == '\n');
}

/*
 * find the index of the boundary, if exists, or optionally the next end of line
 * also returns how many bytes to skip
 */
static int index_of(bufferlist& bl, int max_len, const string& str, bool check_crlf,
                    bool *reached_boundary, int *skip)
{
  *reached_boundary = false;
  *skip = 0;

  if (str.size() < 2) // we assume boundary is at least 2 chars (makes it easier with crlf checks)
    return -EINVAL;

  if (bl.length() < str.size())
    return -1;

  const char *buf = bl.c_str();
  const char *s = str.c_str();

  if (max_len > (int)bl.length())
    max_len = bl.length();

  int i;
  for (i = 0; i < max_len; i++, buf++) {
    if (check_crlf &&
        i >= 1 &&
        is_crlf(buf - 1)) {
        return i + 1; // skip the crlf
    }
    if ((i < max_len - (int)str.size() + 1) &&
        (buf[0] == s[0] && buf[1] == s[1]) &&
        (strncmp(buf, s, str.size()) == 0)) {
      *reached_boundary = true;
      *skip = str.size();

      /* oh, great, now we need to swallow the preceding crlf
       * if exists
       */
      if ((i >= 2) &&
        is_crlf(buf - 2)) {
        i -= 2;
        *skip += 2;
      }
      return i;
    }
  }

  return -1;
}

int RGWPostObj_ObjStore_S3::read_with_boundary(bufferlist& bl, uint64_t max, bool check_crlf,
                                               bool *reached_boundary, bool *done)
{
  uint64_t cl = max + 2 + boundary.size();

  if (max > in_data.length()) {
    uint64_t need_to_read = cl - in_data.length();

    bufferptr bp(need_to_read);

    int read_len;
    s->cio->read(bp.c_str(), need_to_read, &read_len);

    in_data.append(bp, 0, read_len);
  }

  *done = false;
  int skip;
  int index = index_of(in_data, cl, boundary, check_crlf, reached_boundary, &skip);
  if (index >= 0)
    max = index;

  if (max > in_data.length())
    max = in_data.length();

  bl.substr_of(in_data, 0, max);

  bufferlist new_read_data;

  /*
   * now we need to skip boundary for next time, also skip any crlf, or
   * check to see if it's the last final boundary (marked with "--" at the end
   */
  if (*reached_boundary) {
    int left = in_data.length() - max;
    if (left < skip + 2) {
      int need = skip + 2 - left;
      bufferptr boundary_bp(need);
      int actual;
      s->cio->read(boundary_bp.c_str(), need, &actual);
      in_data.append(boundary_bp);
    }
    max += skip; // skip boundary for next time
    if (in_data.length() >= max + 2) {
      const char *data = in_data.c_str();
      if (is_crlf(data + max)) {
	max += 2;
      } else {
        if (*(data + max) == '-' &&
            *(data + max + 1) == '-') {
          *done = true;
	  max += 2;
	}
      }
    }
  }

  new_read_data.substr_of(in_data, max, in_data.length() - max);
  in_data = new_read_data;

  return 0;
}

int RGWPostObj_ObjStore_S3::read_line(bufferlist& bl, uint64_t max,
				  bool *reached_boundary, bool *done)
{
  return read_with_boundary(bl, max, true, reached_boundary, done);
}

int RGWPostObj_ObjStore_S3::read_data(bufferlist& bl, uint64_t max,
				  bool *reached_boundary, bool *done)
{
  return read_with_boundary(bl, max, false, reached_boundary, done);
}


int RGWPostObj_ObjStore_S3::read_form_part_header(struct post_form_part *part,
                                              bool *done)
{
  bufferlist bl;
  bool reached_boundary;
  uint64_t chunk_size = s->cct->_conf->rgw_max_chunk_size;
  int r = read_line(bl, chunk_size, &reached_boundary, done);
  if (r < 0)
    return r;

  if (*done) {
    return 0;
  }

  if (reached_boundary) { // skip the first boundary
    r = read_line(bl, chunk_size, &reached_boundary, done);
    if (r < 0)
      return r;
    if (*done)
      return 0;
  }

  while (true) {
  /*
   * iterate through fields
   */
    string line = rgw_trim_whitespace(string(bl.c_str(), bl.length()));

    if (line.empty())
      break;

    struct post_part_field field;

    string field_name;
    r = parse_part_field(line, field_name, field);
    if (r < 0)
      return r;

    part->fields[field_name] = field;

    if (stringcasecmp(field_name, "Content-Disposition") == 0) {
      part->name = field.params["name"];
    }

    if (reached_boundary)
      break;

    r = read_line(bl, chunk_size, &reached_boundary, done);
  }

  return 0;
}

bool RGWPostObj_ObjStore_S3::part_str(const string& name, string *val)
{
  map<string, struct post_form_part, ltstr_nocase>::iterator iter = parts.find(name);
  if (iter == parts.end())
    return false;

  bufferlist& data = iter->second.data;
  string str = string(data.c_str(), data.length());
  *val = rgw_trim_whitespace(str);
  return true;
}

bool RGWPostObj_ObjStore_S3::part_bl(const string& name, bufferlist *pbl)
{
  map<string, struct post_form_part, ltstr_nocase>::iterator iter = parts.find(name);
  if (iter == parts.end())
    return false;

  *pbl = iter->second.data;
  return true;
}

void RGWPostObj_ObjStore_S3::rebuild_key(string& key)
{
  static string var = "${filename}";
  int pos = key.find(var);
  if (pos < 0)
    return;

  string new_key = key.substr(0, pos);
  new_key.append(filename);
  new_key.append(key.substr(pos + var.size()));

  key = new_key;
}

int RGWPostObj_ObjStore_S3::get_params()
{
  // get the part boundary
  string req_content_type_str = s->info.env->get("CONTENT_TYPE", "");
  string req_content_type;
  map<string, string> params;

  if (s->expect_cont) {
    /* ok, here it really gets ugly. With POST, the params are embedded in the
     * request body, so we need to continue before being able to actually look
     * at them. This diverts from the usual request flow.
     */
    dump_continue(s);
    s->expect_cont = false;
  }

  parse_params(req_content_type_str, req_content_type, params);

  if (req_content_type.compare("multipart/form-data") != 0) {
    err_msg = "Request Content-Type is not multipart/form-data";
    return -EINVAL;
  }

  if (s->cct->_conf->subsys.should_gather(ceph_subsys_rgw, 20)) {
    ldout(s->cct, 20) << "request content_type_str=" << req_content_type_str << dendl;
    ldout(s->cct, 20) << "request content_type params:" << dendl;
    map<string, string>::iterator iter;
    for (iter = params.begin(); iter != params.end(); ++iter) {
      ldout(s->cct, 20) << " " << iter->first << " -> " << iter->second << dendl;
    }
  }

  ldout(s->cct, 20) << "adding bucket to policy env: " << s->bucket.name << dendl;
  env.add_var("bucket", s->bucket.name);

  map<string, string>::iterator iter = params.find("boundary");
  if (iter == params.end()) {
    err_msg = "Missing multipart boundary specification";
    return -EINVAL;
  }

  // create the boundary
  boundary = "--";
  boundary.append(iter->second);

  bool done;
  do {
    struct post_form_part part;
    int r = read_form_part_header(&part, &done);
    if (r < 0)
      return r;
    
    if (s->cct->_conf->subsys.should_gather(ceph_subsys_rgw, 20)) {
      map<string, struct post_part_field, ltstr_nocase>::iterator piter;
      for (piter = part.fields.begin(); piter != part.fields.end(); ++piter) {
        ldout(s->cct, 20) << "read part header: name=" << part.name << " content_type=" << part.content_type << dendl;
        ldout(s->cct, 20) << "name=" << piter->first << dendl;
        ldout(s->cct, 20) << "val=" << piter->second.val << dendl;
        ldout(s->cct, 20) << "params:" << dendl;
        map<string, string>& params = piter->second.params;
        for (iter = params.begin(); iter != params.end(); ++iter) {
          ldout(s->cct, 20) << " " << iter->first << " -> " << iter->second << dendl;
        }
      }
    }

    if (done) { /* unexpected here */
      err_msg = "Malformed request";
      return -EINVAL;
    }

    if (stringcasecmp(part.name, "file") == 0) { /* beginning of data transfer */
      struct post_part_field& field = part.fields["Content-Disposition"];
      map<string, string>::iterator iter = field.params.find("filename");
      if (iter != field.params.end()) {
        filename = iter->second;
      }
      parts[part.name] = part;
      data_pending = true;
      break;
    }

    bool boundary;
    uint64_t chunk_size = s->cct->_conf->rgw_max_chunk_size;
    r = read_data(part.data, chunk_size, &boundary, &done);
    if (!boundary) {
      err_msg = "Couldn't find boundary";
      return -EINVAL;
    }
    parts[part.name] = part;
    string part_str(part.data.c_str(), part.data.length());
    env.add_var(part.name, part_str);
  } while (!done);

  string object_str;
  if (!part_str("key", &object_str)) {
    err_msg = "Key not specified";
    return -EINVAL;
  }

  s->object = rgw_obj_key(object_str);

  rebuild_key(s->object.name);

  if (s->object.empty()) {
    err_msg = "Empty object name";
    return -EINVAL;
  }

  env.add_var("key", s->object.name);

  part_str("Content-Type", &content_type);
  env.add_var("Content-Type", content_type);

  map<string, struct post_form_part, ltstr_nocase>::iterator piter = parts.upper_bound(RGW_AMZ_META_PREFIX);
  for (; piter != parts.end(); ++piter) {
    string n = piter->first;
    if (strncasecmp(n.c_str(), RGW_AMZ_META_PREFIX, sizeof(RGW_AMZ_META_PREFIX) - 1) != 0)
      break;

    string attr_name = RGW_ATTR_PREFIX;
    attr_name.append(n);

    /* need to null terminate it */
    bufferlist& data = piter->second.data;
    string str = string(data.c_str(), data.length());

    bufferlist attr_bl;
    attr_bl.append(str.c_str(), str.size() + 1);

    attrs[attr_name] = attr_bl;
  }

  int r = get_policy();
  if (r < 0)
    return r;

  min_len = post_policy.min_length;
  max_len = post_policy.max_length;

  return 0;
}

int RGWPostObj_ObjStore_S3::get_policy()
{
    bufferlist encoded_policy;
    bool isTokenBasedAuth = (s->auth_method).get_token_validation();
    //(s->auth_method).set_token_validation(false);
    bool isCopyAction = (s->auth_method).get_copy_action();
    (s->auth_method).set_copy_action(false);
    RGWUserInfo user_info;
    string received_signature_str;
    string s3_access_key;
    string iamerror = "";

    if (part_bl("policy", &encoded_policy)) {
        if (!isTokenBasedAuth) {
            // check that the signature matches the encoded policy
            if (!part_str("AWSAccessKeyId", &s3_access_key)) {
                ldout(s->cct, 0) << "No DSS access key found!" << dendl;
                err_msg = "Missing access key";
                return -EINVAL;
            }
            if (!part_str("signature", &received_signature_str)) {
                ldout(s->cct, 0) << "No signature found!" << dendl;
                err_msg = "Missing signature";
                return -EINVAL;
            }
            ret = rgw_get_user_info_by_access_key(store, s3_access_key, user_info);
        }

        if ((ret < 0) || isTokenBasedAuth) {
            // Try keystone authentication as well
            int keystone_result = -EINVAL;
            if (!store->ctx()->_conf->rgw_s3_auth_use_keystone ||
                    store->ctx()->_conf->rgw_keystone_url.empty()) {
                return -EACCES;
            }
            dout(20) << "DSS keystone: trying keystone auth" << dendl;
            RGW_Auth_S3_Keystone_ValidateToken keystone_validator(store->ctx());

            // Get Resource info for keystone
            string errmsg;
            RGWResourceKeystoneInfo resource_info(s, store, isCopyAction);
            if(resource_info.fetchInfo(errmsg)) {
                dout(1) << "DSS Error: " << errmsg << dendl;
                return -EACCES;
            }
            dout(0) << "DSS INFO: Sending Action to validate: " << resource_info.getAction() << dendl;
            dout(0) << "DSS INFO: Sending Resource to validate: " << resource_info.getResourceName() << dendl;
            dout(0) << "DSS INFO: Sending Tenant to validate: " << resource_info.getTenantName() << dendl;

            if (isTokenBasedAuth) {
                keystone_result = keystone_validator.validate_request(resource_info.getAction(),
                                                                      resource_info.getResourceName(),
                                                                      resource_info.getTenantName(),
                                                                      false, /* Is sign auth */
                                                                      false, /* Is copy */
                                                                      false, /* Is cross account */
                                                                      (s->auth_method).get_url_type_token(),
                                                                      resource_info.getCopySrc(),
                                                                      (s->auth_method).get_token(),
                                                                      "",  /* Access key*/
                                                                      "",  /* Canonical string for signature */
                                                                      "", /* Received signature */
                                                                      resource_info.getObjectName(),
                                                                      iamerror);

            } else {
                keystone_result = keystone_validator.validate_request(resource_info.getAction(),
                                                                      resource_info.getResourceName(),
                                                                      resource_info.getTenantName(),
                                                                      true, /* Is sign auth */
                                                                      false, /* Is copy */
                                                                      false, /* Is cross account */
                                                                      (s->auth_method).get_url_type_token(),
                                                                       resource_info.getCopySrc(),
                                                                       "",  /* Token string */
                                                                       s3_access_key,  /* Access key */
                                                                       string(encoded_policy.c_str(),encoded_policy.length()),
                                                                       received_signature_str, /* Received signature */
                                                                       resource_info.getObjectName(),
                                                                       iamerror);

            }

            if (keystone_result < 0) {
                ldout(s->cct, 0) << "User lookup failed!" << dendl;
                if (!isTokenBasedAuth) {
                    err_msg = "Bad access key / signature";
                } else {
                    err_msg = "Bad X-Auth-Token";
                }
                return -EACCES;
            }
            user_info.user_id = keystone_validator.response.token.tenant.id;
            user_info.display_name = keystone_validator.response.token.tenant.id; //<<<<<< DSS needs tenant.name
            /* try to store user if it not already exists */
            if (rgw_get_user_info_by_uid(store, keystone_validator.response.token.tenant.id, user_info) < 0) {
                int ret = rgw_store_user_info(store, user_info, NULL, NULL, 0, true);
                if (ret < 0) {
                    dout(10) << "NOTICE: failed to store new user's info: ret=" << ret << dendl;
                }

                s->perm_mask = RGW_PERM_FULL_CONTROL;
            }
        } else {
            map<string, RGWAccessKey> access_keys  = user_info.access_keys;
            map<string, RGWAccessKey>::const_iterator iter = access_keys.find(s3_access_key);
            // We know the key must exist, since the user was returned by
            // rgw_get_user_info_by_access_key, but it doesn't hurt to check!
            if (iter == access_keys.end()) {
                ldout(s->cct, 0) << "Secret key lookup failed!" << dendl;
                err_msg = "No secret key for matching access key";
                return -EACCES;
            }
            string s3_secret_key = (iter->second).key;

            char expected_signature_char[CEPH_CRYPTO_HMACSHA1_DIGESTSIZE];

            calc_hmac_sha1(s3_secret_key.c_str(), s3_secret_key.size(),
                           encoded_policy.c_str(), encoded_policy.length(),
                           expected_signature_char);
            bufferlist expected_signature_hmac_raw;
            bufferlist expected_signature_hmac_encoded;
            expected_signature_hmac_raw.append(expected_signature_char, CEPH_CRYPTO_HMACSHA1_DIGESTSIZE);
            expected_signature_hmac_raw.encode_base64(expected_signature_hmac_encoded);
            expected_signature_hmac_encoded.append((char)0); /* null terminate */

            if (received_signature_str.compare(expected_signature_hmac_encoded.c_str()) != 0) {
                ldout(s->cct, 0) << "Signature verification failed!" << dendl;
                ldout(s->cct, 0) << "received: " << received_signature_str.c_str() << dendl;
                ldout(s->cct, 0) << "expected: " << expected_signature_hmac_encoded.c_str() << dendl;
                err_msg = "Bad access key / signature";
                return -EACCES;
            }
        }

        if (isTokenBasedAuth) {
            ldout(s->cct, 0) << "Token verification successful!" << dendl;
        } else {
            ldout(s->cct, 0) << "Successful Signature Verification!" << dendl;
        }
        bufferlist decoded_policy;
        try {
            decoded_policy.decode_base64(encoded_policy);
        } catch (buffer::error& err) {
            ldout(s->cct, 0) << "failed to decode_base64 policy" << dendl;
            err_msg = "Could not decode policy";
            return -EINVAL;
        }

        decoded_policy.append('\0'); // NULL terminate
        ldout(s->cct, 0) << "POST policy: " << decoded_policy.c_str() << dendl;
        int r = post_policy.from_json(decoded_policy, err_msg);
        if (r < 0) {
            if (err_msg.empty()) {
                err_msg = "Unknown error occurred in parsing the policy.";
            }
            ldout(s->cct, 0) << "Failed to parse policy. Reason: " << err_msg << dendl;
            return -EINVAL;
        }

        if (!isTokenBasedAuth) {
            post_policy.set_var_checked("AWSAccessKeyId");
            post_policy.set_var_checked("policy");
            post_policy.set_var_checked("signature");
        }

        r = post_policy.check(&env, err_msg);
        if (r < 0) {
            if (err_msg.empty()) {
                err_msg = "Policy check failed";
            }
            ldout(s->cct, 0) << "policy check failed" << dendl;
            return r;
        }
        s->user = user_info;
        s->owner.set_id(user_info.user_id);
        s->owner.set_name(user_info.display_name);
  } else {
    ldout(s->cct, 0) << "No attached policy found!" << dendl;
  }

  string canned_acl;
  part_str("acl", &canned_acl);

  RGWAccessControlPolicy_S3 s3policy(s->cct);
  ldout(s->cct, 20) << "canned_acl=" << canned_acl << dendl;
  if (s3policy.create_canned(s->owner, s->bucket_owner, canned_acl) < 0) {
    err_msg = "Bad canned ACLs";
    return -EINVAL;
  }

  policy = s3policy;
  return 0;
}

int RGWPostObj_ObjStore_S3::complete_get_params()
{
  bool done;
  do {
    struct post_form_part part;
    int r = read_form_part_header(&part, &done);
    if (r < 0)
      return r;
    
    bufferlist part_data;
    bool boundary;
    uint64_t chunk_size = s->cct->_conf->rgw_max_chunk_size;
    r = read_data(part.data, chunk_size, &boundary, &done);
    if (!boundary) {
      return -EINVAL;
    }

    parts[part.name] = part;
  } while (!done);

  return 0;
}

int RGWPostObj_ObjStore_S3::get_data(bufferlist& bl)
{
  bool boundary;
  bool done;

  uint64_t chunk_size = s->cct->_conf->rgw_max_chunk_size;
  int r = read_data(bl, chunk_size, &boundary, &done);
  if (r < 0)
    return r;

  if (boundary) {
    data_pending = false;

    if (!done) {  /* reached end of data, let's drain the rest of the params */
      r = complete_get_params();
      if (r < 0)
        return r;
    }
  }

  return bl.length();
}

void RGWPostObj_ObjStore_S3::send_response()
{
  if (ret == 0 && parts.count("success_action_redirect")) {
    string redirect;

    part_str("success_action_redirect", &redirect);

    string bucket;
    string key;
    string etag_str = "\"";

    etag_str.append(etag);
    etag_str.append("\"");

    string etag_url;

    url_encode(s->bucket_name_str, bucket);
    url_encode(s->object.name, key);
    url_encode(etag_str, etag_url);

    redirect.append("?bucket=");
    redirect.append(bucket);
    redirect.append("&key=");
    redirect.append(key);
    redirect.append("&etag=");
    redirect.append(etag_url);

    int r = check_utf8(redirect.c_str(), redirect.size());
    if (r < 0) {
      ret = r;
      goto done;
    }
    dump_redirect(s, redirect);
    ret = STATUS_REDIRECT;
  } else if (ret == 0 && parts.count("success_action_status")) {
    string status_string;
    uint32_t status_int;

    part_str("success_action_status", &status_string);

    int r = stringtoul(status_string, &status_int);
    if (r < 0) {
      ret = r;
      goto done;
    }

    switch (status_int) {
      case 200:
	break;
      case 201:
	ret = STATUS_CREATED;
	break;
      default:
	ret = STATUS_NO_CONTENT;
	break;
    }
  } else if (!ret) {
    ret = STATUS_NO_CONTENT;
  }

done:
  if (ret == STATUS_CREATED) {
    s->formatter->open_object_section("PostResponse");
    if (g_conf->rgw_dns_name.length())
      s->formatter->dump_format("Location", "%s/%s", s->info.script_uri.c_str(), s->object.name.c_str());
    s->formatter->dump_string("Bucket", s->bucket_name_str);
    s->formatter->dump_string("Key", s->object.name);
    s->formatter->close_section();
  }
  s->err.message = err_msg;
  set_req_state_err(s, ret);
  dump_errno(s);
  if (ret >= 0) {
    dump_content_length(s, s->formatter->get_len());
  }
  end_header(s, this);
  if (ret != STATUS_CREATED)
    return;

  rgw_flush_formatter_and_reset(s, s->formatter);
}


void RGWDeleteObj_ObjStore_S3::send_response()
{
  int r = ret;
  if (r == -ENOENT)
    r = 0;
  if (!r)
    r = STATUS_NO_CONTENT;

  set_req_state_err(s, r);
  dump_errno(s);
  if (!version_id.empty()) {
    dump_string_header(s, "x-jcs-version-id", version_id.c_str());
  }
  if (delete_marker) {
    dump_string_header(s, "x-jcs-delete-marker", "true");
  }
  end_header(s, this);
}

int RGWCopyObj_ObjStore_S3::init_dest_policy()
{
  RGWAccessControlPolicy_S3 s3policy(s->cct);

  /* build a policy for the target object */
  int r = create_s3_policy(s, store, s3policy, s->owner);
  if (r < 0)
    return r;

  dest_policy = s3policy;

  return 0;
}

int RGWCopyObj_ObjStore_S3::get_params()
{
  if_mod = s->info.env->get("HTTP_X_AMZ_COPY_IF_MODIFIED_SINCE");
  if_unmod = s->info.env->get("HTTP_X_AMZ_COPY_IF_UNMODIFIED_SINCE");
  if_match = s->info.env->get("HTTP_X_AMZ_COPY_IF_MATCH");
  if_nomatch = s->info.env->get("HTTP_X_AMZ_COPY_IF_NONE_MATCH");

  src_bucket_name = s->src_bucket_name;
  src_object = s->src_object;
  dest_bucket_name = s->bucket.name;
  dest_object = s->object.name;

  if (s->system_request) {
    source_zone = s->info.args.get(RGW_SYS_PARAM_PREFIX "source-zone");
    if (!source_zone.empty()) {
      client_id = s->info.args.get(RGW_SYS_PARAM_PREFIX "client-id");
      op_id = s->info.args.get(RGW_SYS_PARAM_PREFIX "op-id");

      if (client_id.empty() || op_id.empty()) {
        ldout(s->cct, 0) << RGW_SYS_PARAM_PREFIX "client-id or " RGW_SYS_PARAM_PREFIX "op-id were not provided, required for intra-region copy" << dendl;
        return -EINVAL;
      }
    }
  }

  const char *md_directive = s->info.env->get("HTTP_X_AMZ_METADATA_DIRECTIVE");
  if (md_directive) {
    if (strcasecmp(md_directive, "COPY") == 0) {
      attrs_mod = RGWRados::ATTRSMOD_NONE;
    } else if (strcasecmp(md_directive, "REPLACE") == 0) {
      attrs_mod = RGWRados::ATTRSMOD_REPLACE;
    } else if (!source_zone.empty()) {
      attrs_mod = RGWRados::ATTRSMOD_NONE; // default for intra-region copy
    } else {
      ldout(s->cct, 0) << "invalid metadata directive" << dendl;
      return -EINVAL;
    }
  }

  if (source_zone.empty() &&
      (dest_bucket_name.compare(src_bucket_name) == 0) &&
      (dest_object.compare(src_object.name) == 0) &&
      src_object.instance.empty() &&
      (attrs_mod != RGWRados::ATTRSMOD_REPLACE)) {
    /* can only copy object into itself if replacing attrs */
    ldout(s->cct, 0) << "can't copy object into itself if not replacing attrs" << dendl;
    return -ERR_INVALID_REQUEST;
  }
  return 0;
}

void RGWCopyObj_ObjStore_S3::send_partial_response(off_t ofs)
{
  if (!sent_header) {
    if (ret)
    set_req_state_err(s, ret);
    dump_errno(s);

    end_header(s, this, "application/xml");
    if (ret == 0) {
      s->formatter->open_object_section("CopyObjectResult");
    }
    sent_header = true;
  } else {
    /* Send progress field. Note that this diverge from the original S3
     * spec. We do this in order to keep connection alive.
     */
    s->formatter->dump_int("Progress", (uint64_t)ofs);
  }
  rgw_flush_formatter(s, s->formatter);
}

void RGWCopyObj_ObjStore_S3::send_response()
{
  if (!sent_header)
    send_partial_response(0);

  if (ret == 0) {
    dump_time(s, "LastModified", &mtime);
    if (!etag.empty()) {
      s->formatter->dump_string("ETag", etag);
    }
    s->formatter->close_section();
    rgw_flush_formatter_and_reset(s, s->formatter);
  }
}

void RGWGetACLs_ObjStore_S3::send_response()
{
  if (ret)
    set_req_state_err(s, ret);
  dump_errno(s);
  end_header(s, this, "application/xml");
  dump_start(s);
  rgw_flush_formatter(s, s->formatter);
  s->cio->write(acls.c_str(), acls.size());
}

int RGWPutACLs_ObjStore_S3::get_policy_from_state(RGWRados *store, struct req_state *s, stringstream& ss)
{
  RGWAccessControlPolicy_S3 s3policy(s->cct);

  // bucket-* canned acls do not apply to bucket
  if (s->object.empty()) {
    if (s->canned_acl.find("bucket") != string::npos)
      s->canned_acl.clear();
  }

  int r = create_s3_policy(s, store, s3policy, owner);
  if (r < 0)
    return r;

  s3policy.to_xml(ss);

  return 0;
}

void RGWPutACLs_ObjStore_S3::send_response()
{
  if (ret)
    set_req_state_err(s, ret);
  dump_errno(s);
  end_header(s, this, "application/xml");
  dump_start(s);
}

void RGWGetCORS_ObjStore_S3::send_response()
{
  if (ret) {
    if (ret == -ENOENT) 
      set_req_state_err(s, ERR_NOT_FOUND);
    else 
      set_req_state_err(s, ret);
  }
  dump_errno(s);
  end_header(s, NULL, "application/xml");
  dump_start(s);
  if (!ret) {
    string cors;
    RGWCORSConfiguration_S3 *s3cors = static_cast<RGWCORSConfiguration_S3 *>(&bucket_cors);
    stringstream ss;

    s3cors->to_xml(ss);
    cors = ss.str();
    s->cio->write(cors.c_str(), cors.size());
  }
}

int RGWPutCORS_ObjStore_S3::get_params()
{
  int r;
  char *data = NULL;
  int len = 0;
  size_t cl = 0;
  RGWCORSXMLParser_S3 parser(s->cct);
  RGWCORSConfiguration_S3 *cors_config;

  if (s->length)
    cl = atoll(s->length);
  if (cl) {
    data = (char *)malloc(cl + 1);
    if (!data) {
       r = -ENOMEM;
       goto done_err;
    }
    int read_len;
    r = s->cio->read(data, cl, &read_len);
    len = read_len;
    if (r < 0)
      goto done_err;
    data[len] = '\0';
  } else {
    len = 0;
  }

  if (!parser.init()) {
    r = -EINVAL;
    goto done_err;
  }

  if (!data || !parser.parse(data, len, 1)) {
    r = -EINVAL;
    goto done_err;
  }
  cors_config = static_cast<RGWCORSConfiguration_S3 *>(parser.find_first("CORSConfiguration"));
  if (!cors_config) {
    r = -EINVAL;
    goto done_err;
  }

  if (s->cct->_conf->subsys.should_gather(ceph_subsys_rgw, 15)) {
    ldout(s->cct, 15) << "CORSConfiguration";
    cors_config->to_xml(*_dout);
    *_dout << dendl;
  }

  cors_config->encode(cors_bl);

  free(data);
  return 0;
done_err:
  free(data);
  return r;
}

void RGWPutCORS_ObjStore_S3::send_response()
{
  if (ret)
    set_req_state_err(s, ret);
  dump_errno(s);
  end_header(s, NULL, "application/xml");
  dump_start(s);
}

void RGWDeleteCORS_ObjStore_S3::send_response()
{
  int r = ret;
  if (!r || r == -ENOENT)
    r = STATUS_NO_CONTENT;

  set_req_state_err(s, r);
  dump_errno(s);
  end_header(s, NULL);
}

void RGWOptionsCORS_ObjStore_S3::send_response()
{
  bool is_console_dirty_hack =  s->cct->_conf->rgw_enable_cors_response_headers;
  string hdrs, exp_hdrs;
  uint32_t max_age = CORS_MAX_AGE_INVALID;
  /*EACCES means, there is no CORS registered yet for the bucket
   *ENOENT means, there is no match of the Origin in the list of CORSRule
   */
  if(! is_console_dirty_hack) {
      if (ret == -ENOENT)
          ret = -EACCES;
      if (ret < 0) {
          set_req_state_err(s, ret);
          dump_errno(s);
          end_header(s, NULL);
          return;
      }

      get_response_params(hdrs, exp_hdrs, &max_age);
  } else {
      // clear any error, just send 200 OK in every case
      s->err.clear();
  }
  dump_errno(s);
  if(!is_console_dirty_hack) {
      dump_access_control(s, origin, req_meth, hdrs.c_str(), exp_hdrs.c_str(), max_age); 
  }
  end_header(s, NULL);
}

int RGWInitMultipart_ObjStore_S3::get_params()
{
  RGWAccessControlPolicy_S3 s3policy(s->cct);
  ret = create_s3_policy(s, store, s3policy, s->owner);
  if (ret < 0)
    return ret;

  policy = s3policy;

  return 0;
}

void RGWInitMultipart_ObjStore_S3::send_response()
{
  if (ret)
    set_req_state_err(s, ret);
  dump_errno(s);
  end_header(s, this, "application/xml");
  if (ret == 0) { 
    dump_start(s);
    s->formatter->open_object_section_in_ns("InitiateMultipartUploadResult",
		  (dss_endpoint::endpoint).c_str());
    s->formatter->dump_string("Bucket", s->bucket_name_str);
    s->formatter->dump_string("Key", s->object.name);
    s->formatter->dump_string("UploadId", upload_id);
    s->formatter->close_section();
    rgw_flush_formatter_and_reset(s, s->formatter);
  }
}

void RGWCompleteMultipart_ObjStore_S3::send_response()
{
  if (ret)
    set_req_state_err(s, ret);
  dump_errno(s);
  end_header(s, this, "application/xml");
  if (ret == 0) { 
    dump_start(s);
    s->formatter->open_object_section_in_ns("CompleteMultipartUploadResult",
			  (dss_endpoint::endpoint).c_str());
    if (s->info.domain.length())
      s->formatter->dump_format("Location", "%s.%s", s->bucket_name_str.c_str(), s->info.domain.c_str());
    s->formatter->dump_string("Bucket", s->bucket_name_str);
    s->formatter->dump_string("Key", s->object.name);
    s->formatter->dump_string("ETag", etag);
    s->formatter->close_section();
    rgw_flush_formatter_and_reset(s, s->formatter);
  }
}

void RGWAbortMultipart_ObjStore_S3::send_response()
{
  int r = ret;
  if (!r)
    r = STATUS_NO_CONTENT;

  set_req_state_err(s, r);
  dump_errno(s);
  end_header(s, this);
}

void RGWListMultipart_ObjStore_S3::send_response()
{
  if (ret)
    set_req_state_err(s, ret);
  dump_errno(s);
  end_header(s, this, "application/xml");

  if (ret == 0) { 
    dump_start(s);
    s->formatter->open_object_section_in_ns("ListPartsResult",
		    (dss_endpoint::endpoint).c_str());
    map<uint32_t, RGWUploadPartInfo>::iterator iter;
    map<uint32_t, RGWUploadPartInfo>::reverse_iterator test_iter;
    int cur_max = 0;

    iter = parts.begin();
    test_iter = parts.rbegin();
    if (test_iter != parts.rend()) {
      cur_max = test_iter->first;
    }
    s->formatter->dump_string("Bucket", s->bucket_name_str);
    s->formatter->dump_string("Key", s->object.name);
    s->formatter->dump_string("UploadId", upload_id);
    s->formatter->dump_string("StorageClass", "STANDARD");
    s->formatter->dump_int("PartNumberMarker", marker);
    s->formatter->dump_int("NextPartNumberMarker", cur_max);
    s->formatter->dump_int("MaxParts", max_parts);
    s->formatter->dump_string("IsTruncated", (truncated ? "true" : "false"));

    ACLOwner& owner = policy.get_owner();
    dump_owner(s, owner.get_id(), owner.get_display_name());

    for (; iter != parts.end(); ++iter) {
      RGWUploadPartInfo& info = iter->second;

      time_t sec = info.modified.sec();
      struct tm tmp;
      gmtime_r(&sec, &tmp);
      char buf[TIME_BUF_SIZE];

      s->formatter->open_object_section("Part");

      if (strftime(buf, sizeof(buf), "%Y-%m-%dT%T.000Z", &tmp) > 0) {
        s->formatter->dump_string("LastModified", buf);
      }

      s->formatter->dump_unsigned("PartNumber", info.num);
      s->formatter->dump_string("ETag", info.etag);
      s->formatter->dump_unsigned("Size", info.size);
      s->formatter->close_section();
    }
    s->formatter->close_section();
    rgw_flush_formatter_and_reset(s, s->formatter);
  }
}

void RGWListBucketMultiparts_ObjStore_S3::send_response()
{
  if (ret < 0)
    set_req_state_err(s, ret);
  dump_errno(s);

  end_header(s, this, "application/xml");
  dump_start(s);
  if (ret < 0)
    return;

  s->formatter->open_object_section("ListMultipartUploadsResult");
  s->formatter->dump_string("Bucket", s->bucket_name_str);
  if (!prefix.empty())
    s->formatter->dump_string("ListMultipartUploadsResult.Prefix", prefix);
  string& key_marker = marker.get_key();
  if (!key_marker.empty())
    s->formatter->dump_string("KeyMarker", key_marker);
  string& upload_id_marker = marker.get_upload_id();
  if (!upload_id_marker.empty())
    s->formatter->dump_string("UploadIdMarker", upload_id_marker);
  string next_key = next_marker.mp.get_key();
  if (!next_key.empty())
    s->formatter->dump_string("NextKeyMarker", next_key);
  string next_upload_id = next_marker.mp.get_upload_id();
  if (!next_upload_id.empty())
    s->formatter->dump_string("NextUploadIdMarker", next_upload_id);
  s->formatter->dump_int("MaxUploads", max_uploads);
  if (!delimiter.empty())
    s->formatter->dump_string("Delimiter", delimiter);
  s->formatter->dump_string("IsTruncated", (is_truncated ? "true" : "false"));

  if (ret >= 0) {
    vector<RGWMultipartUploadEntry>::iterator iter;
    for (iter = uploads.begin(); iter != uploads.end(); ++iter) {
      RGWMPObj& mp = iter->mp;
      s->formatter->open_array_section("Upload");
      s->formatter->dump_string("Key", mp.get_key());
      s->formatter->dump_string("UploadId", mp.get_upload_id());
      dump_owner(s, s->user.user_id, s->user.display_name, "Initiator");
      dump_owner(s, s->user.user_id, s->user.display_name);
      s->formatter->dump_string("StorageClass", "STANDARD");
      time_t mtime = iter->obj.mtime.sec();
      dump_time(s, "Initiated", &mtime);
      s->formatter->close_section();
    }
    if (!common_prefixes.empty()) {
      s->formatter->open_array_section("CommonPrefixes");
      map<string, bool>::iterator pref_iter;
      for (pref_iter = common_prefixes.begin(); pref_iter != common_prefixes.end(); ++pref_iter) {
        s->formatter->dump_string("CommonPrefixes.Prefix", pref_iter->first);
      }
      s->formatter->close_section();
    }
  }
  s->formatter->close_section();
  rgw_flush_formatter_and_reset(s, s->formatter);
}

void RGWDeleteMultiObj_ObjStore_S3::send_status()
{
  if (!status_dumped) {
    if (ret < 0)
      set_req_state_err(s, ret);
    dump_errno(s);
    status_dumped = true;
  }
}

void RGWDeleteMultiObj_ObjStore_S3::begin_response()
{

  if (!status_dumped) {
    send_status();
  }

  dump_start(s);
  end_header(s, this, "application/xml");
  s->formatter->open_object_section_in_ns("DeleteResult",
                                          (dss_endpoint::endpoint).c_str());

  rgw_flush_formatter(s, s->formatter);
}

void RGWDeleteMultiObj_ObjStore_S3::send_partial_response(rgw_obj_key& key, bool delete_marker,
                                                          const string& marker_version_id, int ret)
{
  if (!key.empty()) {
    if (ret == 0 && !quiet) {
      s->formatter->open_object_section("Deleted");
      s->formatter->dump_string("Key", key.name);
      if (!key.instance.empty()) {
        s->formatter->dump_string("VersionId", key.instance);
      }
      if (delete_marker) {
        s->formatter->dump_bool("DeleteMarker", true);
        s->formatter->dump_string("DeleteMarkerVersionId", marker_version_id);
      }
      s->formatter->close_section();
    } else if (ret < 0) {
      struct rgw_http_errors r;
      int err_no;

      s->formatter->open_object_section("Error");

      err_no = -ret;
      rgw_get_errno_s3(&r, err_no);

      s->formatter->dump_string("Key", key.name);
      s->formatter->dump_string("VersionId", key.instance);
      s->formatter->dump_int("Code", r.http_ret);
      s->formatter->dump_string("Message", r.s3_code);
      s->formatter->close_section();
    }

    rgw_flush_formatter(s, s->formatter);
  }
}

void RGWDeleteMultiObj_ObjStore_S3::end_response()
{

  s->formatter->close_section();
  rgw_flush_formatter_and_reset(s, s->formatter);
}

RGWOp *RGWHandler_ObjStore_Service_S3::op_get()
{
  return new RGWListBuckets_ObjStore_S3;
}

RGWOp *RGWHandler_ObjStore_Service_S3::op_head()
{
  return new RGWListBuckets_ObjStore_S3;
}

RGWOp *RGWHandler_ObjStore_Bucket_S3::get_obj_op(bool get_data)
{
  if (get_data)
    return new RGWListBucket_ObjStore_S3;
  else
    return new RGWStatBucket_ObjStore_S3;
}

RGWOp *RGWHandler_ObjStore_Bucket_S3::op_get()
{
  if (s->info.args.sub_resource_exists("logging"))
    return new RGWGetBucketLogging_ObjStore_S3;

  if (s->info.args.sub_resource_exists("location"))
    return new RGWGetBucketLocation_ObjStore_S3;

  if (s->info.args.sub_resource_exists("versioning"))
    return new RGWGetBucketVersioning_ObjStore_S3;

  if (is_acl_op()) {
    return new RGWGetACLs_ObjStore_S3;
  } else if (is_cors_op()) {
    return new RGWGetCORS_ObjStore_S3;
  } else if (s->info.args.exists("uploads")) {
    return new RGWListBucketMultiparts_ObjStore_S3;
  }
  return get_obj_op(true);
}

RGWOp *RGWHandler_ObjStore_Bucket_S3::op_head()
{
  if (is_acl_op()) {
    return new RGWGetACLs_ObjStore_S3;
  } else if (s->info.args.exists("uploads")) {
    return new RGWListBucketMultiparts_ObjStore_S3;
  }
  return get_obj_op(false);
}

RGWOp *RGWHandler_ObjStore_Bucket_S3::op_put()
{
  if (s->info.args.sub_resource_exists("logging"))
    return NULL;
  if (s->info.args.sub_resource_exists("versioning"))
    return new RGWSetBucketVersioning_ObjStore_S3;
  if (is_acl_op()) {
    return new RGWPutACLs_ObjStore_S3;
  } else if (is_cors_op()) {
    return new RGWPutCORS_ObjStore_S3;
  } 
  return new RGWCreateBucket_ObjStore_S3;
}

RGWOp *RGWHandler_ObjStore_Bucket_S3::op_delete()
{
  if (is_cors_op()) {
    return new RGWDeleteCORS_ObjStore_S3;
  }
  return new RGWDeleteBucket_ObjStore_S3;
}

RGWOp *RGWHandler_ObjStore_Bucket_S3::op_post()
{
  if ( s->info.request_params == "delete" ) {
    return new RGWDeleteMultiObj_ObjStore_S3;
  }

  return new RGWPostObj_ObjStore_S3;
}

RGWOp *RGWHandler_ObjStore_Bucket_S3::op_options()
{
  return new RGWOptionsCORS_ObjStore_S3;
}

RGWOp *RGWHandler_ObjStore_Obj_S3::get_obj_op(bool get_data)
{
  if (is_acl_op()) {
    return new RGWGetACLs_ObjStore_S3;
  }
  RGWGetObj_ObjStore_S3 *get_obj_op = new RGWGetObj_ObjStore_S3;
  get_obj_op->set_get_data(get_data);
  return get_obj_op;
}

RGWOp *RGWHandler_ObjStore_Obj_S3::op_get()
{
  if (is_acl_op()) {
    return new RGWGetACLs_ObjStore_S3;
  } else if (s->info.args.exists("uploadId")) {
    return new RGWListMultipart_ObjStore_S3;
  }
  return get_obj_op(true);
}

RGWOp *RGWHandler_ObjStore_Obj_S3::op_head()
{
  if (is_acl_op()) {
    return new RGWGetACLs_ObjStore_S3;
  } else if (s->info.args.exists("uploadId")) {
    return new RGWListMultipart_ObjStore_S3;
  }
  return get_obj_op(false);
}

RGWOp *RGWHandler_ObjStore_Obj_S3::op_put()
{
  if (is_acl_op()) {
    return new RGWPutACLs_ObjStore_S3;
  }
  if (!s->copy_source)
    return new RGWPutObj_ObjStore_S3;
  else
    return new RGWCopyObj_ObjStore_S3;
}

RGWOp *RGWHandler_ObjStore_Obj_S3::op_delete()
{
  string upload_id = s->info.args.get("uploadId");

  if (upload_id.empty())
    return new RGWDeleteObj_ObjStore_S3;
  else
    return new RGWAbortMultipart_ObjStore_S3;
}

RGWOp *RGWHandler_ObjStore_Obj_S3::op_post()
{
  if (s->info.args.exists("uploadId"))
    return new RGWCompleteMultipart_ObjStore_S3;

  if (s->info.args.exists("uploads"))
    return new RGWInitMultipart_ObjStore_S3;

  return NULL;
}

RGWOp *RGWHandler_ObjStore_Obj_S3::op_options()
{
  return new RGWOptionsCORS_ObjStore_S3;
}

int RGWHandler_ObjStore_S3::init_from_header(struct req_state *s, int default_formatter, bool configurable_format)
{
  string req;
  string first;

  const char *req_name = s->relative_uri.c_str();
  const char *p;

  if (*req_name == '?') {
    p = req_name;
  } else {
    p = s->info.request_params.c_str();
  }

  s->info.args.set(p);
  s->info.args.parse();

  /* must be called after the args parsing */
  int ret = allocate_formatter(s, default_formatter, configurable_format);
  if (ret < 0)
    return ret;

  if (*req_name != '/')
    return 0;

  req_name++;

  if (!*req_name)
    return 0;

  req = req_name;
  int pos = req.find('/');
  if (pos >= 0) {
    first = req.substr(0, pos);
  } else {
    first = req;
  }

  if (s->bucket_name_str.empty()) {
    s->bucket_name_str = first;

    if (pos >= 0) {
      string encoded_obj_str = req.substr(pos+1);
      s->object = rgw_obj_key(encoded_obj_str, s->info.args.get("versionId"));
    }
  } else {
    s->object = rgw_obj_key(req_name, s->info.args.get("versionId"));
  }
  return 0;
}

static bool looks_like_ip_address(const char *bucket)
{
  int num_periods = 0;
  bool expect_period = false;
  for (const char *b = bucket; *b; ++b) {
    if (*b == '.') {
      if (!expect_period)
	return false;
      ++num_periods;
      if (num_periods > 3)
	return false;
      expect_period = false;
    }
    else if (isdigit(*b)) {
      expect_period = true;
    }
    else {
      return false;
    }
  }
  return (num_periods == 3);
}

static int check_bucket_name_characters_for_relaxed(const string& bucket) {
  for (const char *s = bucket.c_str(); *s; ++s) {
    char c = *s;
    if (isdigit(c) || isalpha(c))
      continue;
    else if ((c == '-') || (c == '_') || (c == '.'))
      continue;
    // Invalid character
    return -ERR_INVALID_BUCKET_NAME;
  }
  return 0;
}

static int check_bucket_name_characters_for_DNS(const string& bucket, int len) {
  // bucket name length cannot exceed 63 characters.
  if (len > 63)
    return -ERR_INVALID_BUCKET_NAME;
  // bucket name must start with either letter or number.
  if (!(isalpha(bucket[0]) || isdigit(bucket[0])))
    return -ERR_INVALID_BUCKET_NAME;
  // bucket name must end with either letter or number.
  if (!(isalpha(bucket[len-1]) || isdigit(bucket[len-1])))
    return -ERR_INVALID_BUCKET_NAME;
  // bucket name cannot contain a sequence of ".-" , ".." or "-."
  bool last_char_dot = false; // last character occurred was a '.'
  bool last_char_hyphen = false; // last character occurred was a '-'
  for (const char *s = bucket.c_str(); *s; ++s) {
    char c = *s;
    // bucket name cannot contain uppercase letters.
    if (isdigit(c) || (isalpha(c) && islower(c))) {
      last_char_hyphen = false;
      last_char_dot = false;
      continue;
    }
    else if (c == '.') {
      if ((last_char_hyphen || last_char_dot))
        return -ERR_INVALID_BUCKET_NAME;
      else {
        last_char_dot = true;
        continue;
      }
    }
    else if (c == '-') {
      if (last_char_dot)
        return -ERR_INVALID_BUCKET_NAME;
      else {
        last_char_hyphen = true;
        continue;
      }
    }
    // Invalid character (cannot contain anything except alphanumeric, '.' and '-' )
    else
      return -ERR_INVALID_BUCKET_NAME;
  }
  return 0;
}

int RGWHandler_ObjStore_S3::validate_bucket_name(const string& bucket, int name_strictness)
{
  int ret = RGWHandler_ObjStore::validate_bucket_name(bucket, name_strictness);
  if (ret < 0)
    return ret;

  int len = bucket.size();
  if (len == 0)
    return 0;

  switch(name_strictness) {
    case 0:
      // bucket name cannot contain anything except alphanumeric, '.', '-' and '_'.
      ret = check_bucket_name_characters_for_relaxed(bucket);
      break;
    case 1:
      // bucket names must start with a number or letter
      if (!(isalpha(bucket[0]) || isdigit(bucket[0])))
        return -ERR_INVALID_BUCKET_NAME;
      // bucket name cannot contain anything except alphanumeric, '.', '-' and '_'.
      ret = check_bucket_name_characters_for_relaxed(bucket);
      break;

    case 2:
      // check other conditions so as to confirm DNS compliance.
      ret = check_bucket_name_characters_for_DNS(bucket, len);
      break;

    default: // default is case 1.
      if (!(isalpha(bucket[0]) || isdigit(bucket[0])))
        return -ERR_INVALID_BUCKET_NAME;
      ret = check_bucket_name_characters_for_relaxed(bucket);
  }

  if (ret < 0 )
    return ret;

  if (looks_like_ip_address(bucket.c_str()))
    return -ERR_INVALID_BUCKET_NAME;

  return 0;
}

int RGWHandler_ObjStore_S3::init(RGWRados *store, struct req_state *s, RGWClientIO *cio)
{
  dout(10) << "s->object=" << (!s->object.empty() ? s->object : rgw_obj_key("<NULL>")) << " s->bucket=" << (!s->bucket_name_str.empty() ? s->bucket_name_str : "<NULL>") << dendl;
  int bucket_name_strictness_value = s->cct->_conf->rgw_s3_bucket_name_access_strictness;
  int ret = validate_bucket_name(s->bucket_name_str, bucket_name_strictness_value);
  if (ret)
    return ret;
  ret = validate_object_name(s->object.name);
  if (ret)
    return ret;

  const char *cacl = s->info.env->get("HTTP_X_AMZ_ACL");
  if (cacl)
    s->canned_acl = cacl;

  s->has_acl_header = s->info.env->exists_prefix("HTTP_X_AMZ_GRANT");

  s->copy_source = s->info.env->get("HTTP_X_JCS_COPY_SOURCE");
  if (!(s->copy_source)) {
    // Try for AMZ header too once
    s->copy_source = s->info.env->get("HTTP_X_AMZ_COPY_SOURCE");
  }

  if (s->copy_source) {
    ret = RGWCopyObj::parse_copy_location(s->copy_source, s->src_bucket_name, s->src_object);
    if (!ret) {
      ldout(s->cct, 0) << "failed to parse copy location" << dendl;
      return -EINVAL;
    }
    ret = validate_bucket_name(s->src_bucket_name, bucket_name_strictness_value);
    if (ret)
      return ret;
    ret = validate_object_name(s->src_object.name);
    if (ret)
      return ret;
  }

  s->dialect = "s3";

  return RGWHandler_ObjStore::init(store, s, cio);
}

/* Validate Request against IAM */
int RGW_Auth_S3_Keystone_ValidateToken::validate_request(const string& action,
                                                         const string& resource_name,
                                                         const string& tenant_name,
                                                         const bool&   is_sign_auth,
                                                         const bool&   is_copy,
                                                         const bool&   is_cross_account,
                                                         const bool&   is_url_token,
                                                         const string& copy_src,
                                                         const string& token,
                                                         const string& auth_id,
                                                         const string& auth_token,
                                                         const string& auth_sign,
                                                         const string& objectname,
                                                         string& iamerror)
{
  int ret = 0;
  string localAction = action;
  string rootAccount = "";

  /* Certain actions are never cross account
   * Dont try a cross account call for them */
  bool is_non_rc_action = false;
  is_non_rc_action = ((localAction.compare("CreateBucket") == 0)
                   || (localAction.compare("ListAllMyBuckets") == 0)
                   || is_url_token);

  /* Set required headers for keystone request
   * Recursive calls already have headers set */
  if (!is_copy && !is_cross_account) {
      if (!is_sign_auth) {
          if (is_url_token) {
              append_header("X-Url-Token", token);
          } else {
              append_header("X-Auth-Token", token);
          }
      }
      append_header("Content-Type", "application/json");
  }

  /* Handle special case of copy */
  bool isCopyAction  = false;
  isCopyAction = (localAction.compare("CopyObject") == 0);
  if (isCopyAction) {
      // Make recursive call with is_copy set to
      // true and resource set to copy source
      localAction = "GetObject";
      int pos = copy_src.find(':');
      string copy_src_str = copy_src.substr(0, pos);
      string copy_src_tenant = copy_src.substr(pos + 1);
      dout(0) << "DSS INFO: Validating for copy source" << dendl;
      ret = validate_request(localAction, copy_src_str, copy_src_tenant, is_sign_auth,
                             true, is_cross_account, is_url_token, copy_src,
                             token, auth_id, auth_token, auth_sign, objectname, iamerror);
      if (ret < 0) {
          return ret;
      } else {
          dout(0) << "DSS INFO: Validating for copy destination" << dendl;
          localAction = "PutObject";
      }
  }

  // For cross account call, get root account ID
  if (is_cross_account) {
      if (tenant_name.size() > 0) {
          rootAccount = tenant_name;
      } else {
          // root account was not populated. Error out.
          return -ENOTRECOVERABLE;
      }
  } else {
      rootAccount = "";
  }

  /* prepare keystone url */
  string implicit_allow = "False";
  string action_str = "jrn:jcs:dss:";
  action_str.append(localAction);
  string resource_str = "jrn:jcs:dss:";
  resource_str.append(rootAccount);
  resource_str.append(":Bucket:");
  resource_str.append(resource_name);

  string keystone_url = cct->_conf->rgw_keystone_url;
  if (keystone_url[keystone_url.size() - 1] != '/') {
    keystone_url.append("/");
  }
  if (is_sign_auth) {
      keystone_url.append(cct->_conf->rgw_keystone_sign_api);
      if (is_cross_account) {
          keystone_url.append("-ex");
      }
      dout(0) << "DSS INFO: Validating Signature" << dendl;
  } else if (is_url_token) {
      keystone_url.append(cct->_conf->rgw_keystone_url_token_api);
      dout(0) << "DSS INFO: Validating presigned URL token" << dendl;
  } else {
      keystone_url.append(cct->_conf->rgw_keystone_token_api);
      if (is_cross_account) {
          keystone_url.append("-ex");
      }
      dout(0) << "DSS INFO: Validating Console token" << dendl;
  }

  dout(0) << "DSS INFO: Action string: " << action_str << dendl;
  dout(0) << "DSS INFO: Resource string: " << resource_str << dendl;
  dout(0) << "DSS INFO: Final URL: " << keystone_url << dendl;

  /* encode token */
  bufferlist token_buff;
  bufferlist token_encoded;
  token_buff.append(auth_token);
  token_buff.encode_base64(token_encoded);
  token_encoded.append((char)0);
  string cannonical_str(token_encoded.c_str());

  /* create json credentials request body */
  JSONFormatter credentials(false);
  credentials.open_object_section("");
  if (is_sign_auth) {
      credentials.open_object_section("credentials");
      credentials.dump_string("access", auth_id.c_str());
      credentials.dump_string("token", cannonical_str.c_str());
      credentials.dump_string("signature", auth_sign.c_str());
  }
  credentials.open_array_section("action_resource_list");
  credentials.open_object_section("");
  credentials.dump_string("action", action_str.c_str());
  credentials.dump_string("resource", resource_str.c_str());
  if (is_url_token) {
      credentials.dump_string("object_name", objectname.c_str());
  } else {
      credentials.dump_string("implicit_allow", implicit_allow.c_str());
  }
  credentials.close_section();
  credentials.close_section();
  if (is_sign_auth) {
      credentials.close_section();
  }
  credentials.close_section();
  std::stringstream os;
  credentials.flush(os);
  set_tx_buffer(os.str()); // clears automatically
  string bufferprinter = "";
  tx_buffer.copy(0, tx_buffer.length(), bufferprinter);
  dout(0) << "DSS INFO: \n\n" << dendl;
  dout(0) << "DSS INFO: Outbound json: " << os.str() << dendl;
  dout(0) << "DSS INFO: \n\n" << dendl;
  dout(0) << "DSS INFO: Actual TX buffer: " << bufferprinter << dendl;
  dout(0) << "DSS INFO: \n\n" << dendl;

  /* Make request to IAM */
  ret = make_iam_request(keystone_url, iamerror);
  if (ret < 0) {
      if (is_cross_account) {
          // If a cross account call has failed,
          // make sure the bucket is not public
          bool is_public_bucket = false;
          string reason;
          reason = "";
          RGWResourceKeystoneInfo bucket_info;
          if(!bucket_info.get_bucket_public_perm(localAction, resource_name, is_public_bucket, reason)) {
              dout(0) << "DSS ERROR: Failed to fetch public permissions on bucket: "
                      << resource_name
                      << ". Reason: "
                      << reason
                      << dendl;
              return -EACCES;
          }
          if (is_public_bucket) {
              return 0;
          }
      }
      return ret;
  }

  if (is_cross_account) {
      // IAM validation successful. Avoid going in a recursive loop.
      return 0;
  }

  /* Check root account ID of the caller against resource name */
  string keystoneTenant = response.token.tenant.id;
  if (!is_non_rc_action && (keystoneTenant.compare(tenant_name) != 0)) {
      // This case requires cross account validation.
      // Make recursive call with is_cross_account set to true
      dout(0) << "DSS INFO: Validating for cross account access" << dendl;
      ret = validate_request(localAction, resource_name, tenant_name,
                             is_sign_auth, is_copy, true,
                             is_url_token, copy_src, token, auth_id,
                             auth_token, auth_sign, objectname, iamerror);
      if (ret < 0) {
          return ret;
      }
  }

  /* everything seems fine, continue with this user */
  ldout(cct, 5) << "DSS INFO: keystone validated token for (root account id : user id) "
                << response.token.tenant.id << ":"
                << response.user.id << dendl;
  return 0;
}

/* Make the CURL call to IAM
 * Call to this function requires tx_buffer to be set beforehand */
int RGW_Auth_S3_Keystone_ValidateToken::make_iam_request(const string& keystone_url, string& iamerror)
{
  /* Clear the buffers */
  rx_buffer.clear();
  rx_headers_buffer.clear();
  string bufferprinter = "";
  string bufferheaderprinter = "";

  /* send request */
  utime_t begin_time = ceph_clock_now(g_ceph_context);
  int ret = process("POST", keystone_url.c_str());
  utime_t end_time = ceph_clock_now(g_ceph_context);
  end_time = end_time - begin_time;
  dout(0) << "DSS INFO: Keystone response time (milliseconds): " << end_time.to_msec() << dendl;
  rx_buffer.copy(0, rx_buffer.length(), bufferprinter);
  rx_headers_buffer.copy(0, rx_headers_buffer.length(), bufferheaderprinter);
  if (ret < 0) {
    dout(2) << "DSS ERROR: keystone validation error: " << bufferprinter << dendl;
    return -EPERM;
  }
  dout(0) << "DSS INFO: Printing RX buffer: " << bufferprinter << dendl;
  dout(0) << "DSS INFO: Printing RX headers: " << bufferheaderprinter << dendl;


  /* Populate iamerror */
  char *rxbuffer = strdup(bufferprinter.c_str());
  char *savedptr;
  char *p = strtok_r(rxbuffer, "\"" , &savedptr);
  vector<string> tokens;
  while (p) {
      string tok = p;
      tokens.push_back(tok);
      p = strtok_r(NULL, "\"", &savedptr);
  }
  // assuming error from IAM is always in this format
  // {"error": {"message": "The resource could not be found.", "code": 404, "title": "Not Found"}}
  if(tokens.size() >= 5 && !strcmp(tokens[1].c_str(), "error") && !strcmp(tokens[3].c_str(), "message")) {
    iamerror = "IAM_ERROR: " +  tokens[5];
  }
  free(rxbuffer);


  /* now parse response */
  if (response.parse(cct, rx_buffer) < 0) {
    dout(2) << "DSS ERROR: keystone: Response parsing failed" << dendl;
    return -EPERM;
  }

  /* Check if the response is okay */
  if ((response.user.id).empty()   ||
      (response.token.tenant.id).empty()) {
      dout(0) << "DSS ERROR: Response empty. "
              << " Root account ID: "
              << response.token.tenant.id.c_str()
              << " User ID: "
              << response.user.id.c_str()
              << dendl;
      return -EPERM;
  }

  return 0;
}

static void init_anon_user(struct req_state *s)
{
  rgw_get_anon_user(s->user);
  s->perm_mask = RGW_PERM_FULL_CONTROL;
}

/*
 * verify that a signed request comes from the keyholder
 * by checking the signature against our locally-computed version
 */
int RGW_Auth_S3::authorize(RGWRados *store, struct req_state *s)
{
  bool qsr = false;
  string auth_id;
  string auth_sign;
  time_t now;
  time(&now);
  string iamerror = "";

  // Get request header related DSS info
  dss_endpoint::endpoint = store->ctx()->_conf->dss_regional_url;
  bool isTokenBasedAuth = (s->auth_method).get_token_validation();
  bool isCopyAction = (s->auth_method).get_copy_action();

  // check for token in presigned URL requests
  if(!isTokenBasedAuth && store->ctx()->_conf->rgw_enable_token_based_presigned_url) {
      string url_token = s->info.args.get("X-Url-Token");
      if(url_token.size() > 0) {
          isTokenBasedAuth = true;
          (s->auth_method).set_token_validation(true);
          (s->auth_method).set_token(url_token);
          (s->auth_method).set_url_type_token(true);
      }
  }

  // Block any ACL request for DSS
  string qstring = (s->info).request_params;
  if (store->ctx()->_conf->rgw_disable_acl_api && (qstring.compare("acl") == 0)) {
      dout(0) << "DSS INFO: ACL requests are not supported" << dendl;
      return -EPERM;
  }

  /* neither keystone and rados enabled; warn and exit! */
  if (!store->ctx()->_conf->rgw_s3_auth_use_rados
      && !store->ctx()->_conf->rgw_s3_auth_use_keystone) {
    dout(0) << "WARNING: no authorization backend enabled! Users will never authenticate." << dendl;
    return -EPERM;
  }

  if (s->op == OP_OPTIONS) {
    init_anon_user(s);
    return 0;
  }

  if (!isTokenBasedAuth) {
      if (!s->http_auth || !(*s->http_auth)) {
          /* try both JCSAccessKeyId and AWSAccessKeyId for
           * the time being otherwise boto apis will fail */
          auth_id = s->info.args.get("JCSAccessKeyId");
          if(!auth_id.size()) {
            auth_id = s->info.args.get("AWSAccessKeyId");
          }
          if (auth_id.size()) {
              auth_sign = s->info.args.get("Signature");
              string date = s->info.args.get("Expires");
              time_t exp = atoll(date.c_str());
              if (now >= exp)
                  return -EPERM;
              qsr = true;
          } else {
              /* anonymous access */
              //<<<<<< You will hit here for sign based req
              //<<<<<< Add changes for anonymous access. Call a func from here.
              init_anon_user(s);
              return 0;
          }
      } else {
          // strncmp returns 0 on match. If even one of AWS or JCS match, dont return -EINVAL.
          if ((strncmp(s->http_auth, "AWS ", 4)) && (strncmp(s->http_auth, "JCS ", 4)))
              return -EINVAL;
          string auth_str(s->http_auth + 4);
          int pos = auth_str.rfind(':');
          if (pos < 0)
              return -EINVAL;
          auth_id = auth_str.substr(0, pos);
          auth_sign = auth_str.substr(pos + 1);
      }
  } else {
      // DSS console token validation:
      // Don't want time skew check as tokens expire periodically
      // keystone will take care of this
      qsr = true;
  }

  /* try keystone auth first */
  int keystone_result = -EINVAL;
  if (store->ctx()->_conf->rgw_s3_auth_use_keystone
      && !store->ctx()->_conf->rgw_keystone_url.empty()) {

    dout(0) << "DSS INFO: keystone: Trying keystone auth" << dendl;
    RGW_Auth_S3_Keystone_ValidateToken keystone_validator(store->ctx());

    /* Make canonical string */
    string token;
  //  s3->err.message = "";
    if (!isTokenBasedAuth &&
       (!rgw_create_s3_canonical_header(s->info, &s->header_time, token, qsr))) {
        dout(10) << "Failed to create auth header\n" << token << dendl;
    } else {

      // Get Resource info for keystone
      string errmsg;
      RGWResourceKeystoneInfo resource_info(s, store, isCopyAction);
      if(resource_info.fetchInfo(errmsg)) {
          dout(0) << "DSS Error: " << errmsg << dendl;
          return -EACCES;
      }

      string resource_object_name = "";
      if (s != NULL) {
          resource_object_name = s->object.name;
      }
      dout(0) << "DSS INFO: Sending Action to validate: " << resource_info.getAction() << dendl;
      dout(0) << "DSS INFO: Sending Resource to validate: " << resource_info.getResourceName() << dendl;
      dout(0) << "DSS INFO: Sending Tenant to validate: " << resource_info.getTenantName() << dendl;
      dout(0) << "DSS INFO: Sending Object to validate: " << resource_object_name << dendl;

      if (isTokenBasedAuth) {
          keystone_result = keystone_validator.validate_request(resource_info.getAction(),
                                                                resource_info.getResourceName(),
                                                                resource_info.getTenantName(),
                                                                false, /* Is sign auth */
                                                                false, /* Is copy */
                                                                false, /* Is cross account */
                                                                (s->auth_method).get_url_type_token(),
                                                                resource_info.getCopySrc(),
                                                                (s->auth_method).get_token(),
                                                                "",  /* Access key*/
                                                                "",  /* Canonical string for signature */
                                                                "",  /* Received signature */
                                                                resource_object_name,
                                                                iamerror);
        
      } else {
          keystone_result = keystone_validator.validate_request(resource_info.getAction(),
                                                                resource_info.getResourceName(),
                                                                resource_info.getTenantName(),
                                                                true, /* Is sign auth */
                                                                false, /* Is copy */
                                                                false, /* Is cross account */
                                                                (s->auth_method).get_url_type_token(),
                                                                resource_info.getCopySrc(),
                                                                "",  /* Token string */
                                                                auth_id,  /* Access key */
                                                                token,  /* Canonical string for signature */
                                                                auth_sign, /* Received signature */
                                                                resource_object_name,
                                                                iamerror);

      }


      if (keystone_result == 0) {

        // Check for time skew first
        time_t req_sec = s->header_time.sec();
        if ((req_sec < now - RGW_AUTH_GRACE_MINS * 60 ||
             req_sec > now + RGW_AUTH_GRACE_MINS * 60) && !qsr) {
         dout(10) << "req_sec=" << req_sec << " now="
                  << now << "; now - RGW_AUTH_GRACE_MINS="
                  << now - RGW_AUTH_GRACE_MINS * 60
                  << "; now + RGW_AUTH_GRACE_MINS="
                  << now + RGW_AUTH_GRACE_MINS * 60 << dendl;
         dout(0) << "NOTICE: request time skew too big now="
                 << utime_t(now, 0) << " req_time=" << s->header_time << dendl;
         return -ERR_REQUEST_TIME_SKEWED;
        }

        string tenant_id_str = keystone_validator.response.token.tenant.id;
        /*tenant_id_str = tenant_id_str.substr(tenant_id_str.size() - 12);
        dout(0) << "DSS INFO: Ignoring root account ID zeroes: "
                << keystone_validator.response.token.tenant.id << " to "
                << tenant_id_str
                << dendl;*/

        s->user.user_id = tenant_id_str;
        s->user.display_name = tenant_id_str;
        (s->auth_method).set_acl_main_override(true);

        /* try to store user if it not already exists */
        if (rgw_get_user_info_by_uid(store, keystone_validator.response.token.tenant.id, s->user) < 0) {
          int ret = rgw_store_user_info(store, s->user, NULL, NULL, 0, true);
          if (ret < 0)
            dout(10) << "NOTICE: failed to store new user's info: ret=" << ret << dendl;
        }
        s->perm_mask = RGW_PERM_FULL_CONTROL;
      }
    }
  }

  /* keystone failed (or not enabled); check if we want to use rados backend */
  if (!store->ctx()->_conf->rgw_s3_auth_use_rados
      && keystone_result < 0)
    return keystone_result;

  /* now try rados backend, but only if keystone did not succeed */
  if (keystone_result < 0) {
    /* get the user info */
    if (rgw_get_user_info_by_access_key(store, auth_id, s->user) < 0) {
      if (iamerror != "" ) {
        s->err.message = iamerror;
      }
      dout(5) << "error reading user info, uid=" << auth_id << " can't authenticate" << dendl;
      return -ERR_INVALID_ACCESS_KEY;
    }

    /* now verify signature */
    string auth_hdr;
    if (!rgw_create_s3_canonical_header(s->info, &s->header_time, auth_hdr, qsr)) {
      dout(10) << "failed to create auth header\n" << auth_hdr << dendl;
      return -EPERM;
    }
    dout(10) << "auth_hdr:\n" << auth_hdr << dendl;

    time_t req_sec = s->header_time.sec();
    if ((req_sec < now - RGW_AUTH_GRACE_MINS * 60 ||
         req_sec > now + RGW_AUTH_GRACE_MINS * 60) && !qsr) {
      dout(10) << "req_sec=" << req_sec
               << " now=" << now << "; now - RGW_AUTH_GRACE_MINS="
               << now - RGW_AUTH_GRACE_MINS * 60 << "; now + RGW_AUTH_GRACE_MINS="
               << now + RGW_AUTH_GRACE_MINS * 60 << dendl;
      dout(0) << "NOTICE: request time skew too big now="
              << utime_t(now, 0) << " req_time=" << s->header_time << dendl;
      return -ERR_REQUEST_TIME_SKEWED;
    }

    map<string, RGWAccessKey>::iterator iter = s->user.access_keys.find(auth_id);
    if (iter == s->user.access_keys.end()) {
      dout(0) << "ERROR: access key not encoded in user info" << dendl;
      return -EPERM;
    }
    RGWAccessKey& k = iter->second;

    if (!k.subuser.empty()) {
      map<string, RGWSubUser>::iterator uiter = s->user.subusers.find(k.subuser);
      if (uiter == s->user.subusers.end()) {
        dout(0) << "NOTICE: could not find subuser: " << k.subuser << dendl;
        return -EPERM;
      }
      RGWSubUser& subuser = uiter->second;
      s->perm_mask = subuser.perm_mask;
    } else {
      s->perm_mask = RGW_PERM_FULL_CONTROL;
    }

    string digest;
    int ret = rgw_get_s3_header_digest(auth_hdr, k.key, digest);
    if (ret < 0) {
      return -EPERM;
    }

    dout(15) << "calculated digest=" << digest << dendl;
    dout(15) << "auth_sign=" << auth_sign << dendl;
    dout(15) << "compare=" << auth_sign.compare(digest) << dendl;

    if (auth_sign != digest) {
      return -ERR_SIGNATURE_NO_MATCH;
    }

    if (s->user.system) {
      s->system_request = true;
      dout(20) << "system request" << dendl;
      s->info.args.set_system();
      string effective_uid = s->info.args.get(RGW_SYS_PARAM_PREFIX "uid");
      RGWUserInfo effective_user;
      if (!effective_uid.empty()) {
        ret = rgw_get_user_info_by_uid(store, effective_uid, effective_user);
        if (ret < 0) {
          ldout(s->cct, 0) << "User lookup failed!" << dendl;
          return -ENOENT;
        }
        s->user = effective_user;
      }
    }

  } /* if keystone_result < 0 */

  // populate the owner info
  s->owner.set_id(s->user.user_id);
  s->owner.set_name(s->user.display_name);

  return  0;
}

int RGWHandler_Auth_S3::init(RGWRados *store, struct req_state *state, RGWClientIO *cio)
{
  int ret = RGWHandler_ObjStore_S3::init_from_header(state, RGW_FORMAT_JSON, true);
  if (ret < 0)
    return ret;

  return RGWHandler_ObjStore::init(store, state, cio);
}

RGWHandler *RGWRESTMgr_S3::get_handler(struct req_state *s)
{
  int ret = RGWHandler_ObjStore_S3::init_from_header(s, RGW_FORMAT_XML, false);
  if (ret < 0)
    return NULL;

  if (s->bucket_name_str.empty())
    return new RGWHandler_ObjStore_Service_S3;

  if (s->object.empty())
    return new RGWHandler_ObjStore_Bucket_S3;

  return new RGWHandler_ObjStore_Obj_S3;
}

/*
 * RGWResourceKeystoneInfo::fetchInfo
 *
 * Populates action, resource and tenant
 * name for Keystone validation
 */
uint32_t RGWResourceKeystoneInfo::fetchInfo(string& fail_reason)
{
    string resource_name;
    string query_str;
    int ret = 0;
    fail_reason = "OK";
    bool obj_action = false;
    int special_action = RGWResourceKeystoneInfo::_none;

    // Populate resource name and query string
    resource_name  = (_s->info).request_uri;
    query_str      = (_s->info).request_params;
    string copyStr = (_s->auth_method).get_copy_source();

    RGWObjectCtx& obj_ctx = *(RGWObjectCtx *)_s->obj_ctx;
    if (!resource_name.empty()) {
        const char *src = resource_name.c_str();
        if (*src == '/')
            ++src;
        string bucket_str(src);

        //get_all_buckets() case
        if (bucket_str.empty()) {
            fail_reason = "No bucket received. This is the get all buckets case.";
            // Populate action string and resource name
            string allResources("*");
            setResourceName(allResources);
            special_action = RGWResourceKeystoneInfo::_list_all_buckets;
            obj_action = false;
            if (fetchActionString(_s->op, obj_action, special_action, fail_reason)) {
                dout(0) << "DSS ERROR: Failed to fetch action string. Reason: " << fail_reason << dendl;
                fail_reason = "Failed to fetch action string. Reason: " + fail_reason;
                return -1;
            }
            return 0;
        }

        int pos = bucket_str.find('/');
        string dummy = "";
        if ((pos < ((signed)bucket_str.length() - 1)) && (pos > 0)) {
            // If you found a pos for '/' and its not at the end like
            // "path/". If its in between "path/a"
            obj_action = true;
            dummy = bucket_str.substr(pos + 1);
            setObjectName(dummy);
        } else {
            dummy = "";
            setObjectName(dummy);
        }

        if (pos > 0) {
            bucket_str = bucket_str.substr(0, pos);
        }
        setResourceName(bucket_str);

        RGWBucketInfo source_info;
        ret = _store->get_bucket_info(obj_ctx, bucket_str, source_info, NULL);
        if (ret == 0) {
            setTenantName(source_info.owner);
            dout(0) << "Found root account ID on resource " << bucket_str
                    << ". Root account: " << getTenantName() << dendl;
        } else {
            // In cases like create bucket or deleting a non existing bucket
            // set tenant name to NULL
            string emptryStr = "";
            setTenantName(emptryStr);
            dout(0) << "Setting root account ID to empty. Got return value: " << ret << dendl;
        }

    } else {
        dout(0) << "DSS ERROR: Failed to fetch resource name" << dendl;
        fail_reason = "Failed to fetch resource name";
        return -1;
    }

    if (getCopyAction()) {
        special_action = RGWResourceKeystoneInfo::_copy_action;
        int pos = copyStr.find('/');
        if (pos > 0) {
            copyStr = copyStr.substr(0, pos);
            string copy_tenant = "";

            RGWBucketInfo source_info;
            ret = _store->get_bucket_info(obj_ctx, copyStr, source_info, NULL);
            if (ret == 0) {
                copy_tenant = source_info.owner;
                dout(0) << "Found root account ID on copy resource " << copyStr
                        << ". Root account: " << copy_tenant << dendl;
            } else {
                // This should never happen here as the bucket mentioned is copy source
                // This will happen when your copy source does not exist. This will
                // error out later by itself.
                copy_tenant = "";
            }
            copyStr.append(":");
            copyStr.append(copy_tenant);
            setCopySrc(copyStr);
        } else {
            // Invalid format for x-jcs-copy-source header
            fail_reason = "Invalid format for x-jcs-copy-source header";
            return -1;
        }
    } else if (query_str.compare("uploads") == 0) {
        special_action = RGWResourceKeystoneInfo::_multipart_upload;
    } else if (query_str.compare(0, 8, "uploadId") == 0) {
        special_action = RGWResourceKeystoneInfo::_multipart_id_action;
    }

    // Populate action string
    if (fetchActionString(_s->op, obj_action, special_action, fail_reason)) {
        dout(0) << "DSS ERROR: Failed to fetch action string. Reason: " << fail_reason << dendl;
        fail_reason = "Failed to fetch action string. Reason: " + fail_reason;
        return -1;
    }

    return 0;
}

/*
 * RGWResourceKeystoneInfo::fetchActionString
 *
 * Populates action based of OP number
 */
uint32_t RGWResourceKeystoneInfo::fetchActionString(uint32_t op,
                                                    bool     object_action,
                                                    int      special_action,
                                                    string&  fail_reason)
{
    fail_reason = "OK";

    // Return error for bad action or options
    if ((op == OP_UNKNOWN) || (op == OP_OPTIONS)) {
        fail_reason = "Bad action requested";
        return -1;
    } else if (op == OP_HEAD) {
        // Get permission implies Head too
        op = OP_GET;
    } else if (op == OP_COPY) {
        if (!object_action) {
            fail_reason = "Copy operation only allowed on objects";
            return -1;
        }
    }

    // Handle special actions that do not match their HTTP verbs
    if (special_action == RGWResourceKeystoneInfo::_copy_action) {
        setAction("CopyObject");
        return 0;
    } else if (special_action == RGWResourceKeystoneInfo::_list_all_buckets) {
        setAction("ListAllMyBuckets");
        return 0;
    } else if (special_action == RGWResourceKeystoneInfo::_multipart_upload) {
        if (op == OP_GET) {
            //List active multipart uploads on a bucket
            setAction("ListBucketMultipartUploads");
        } else if (op == OP_POST) {
            //Initiate multipart upload
            setAction("PutObject");
        } else {
            fail_reason = "Bad action requested";
            return -1;
        }
        return 0;
    } else if (special_action == RGWResourceKeystoneInfo::_multipart_id_action) {
        if (op == OP_PUT) {
            //Upload single part in a multipart upload req
            setAction("PutObject");
        } else if (op == OP_POST) {
            //Complete multipart upload
            setAction("PutObject");
        } else if (op == OP_DELETE) {
            //Delete multipart upload
            setAction("AbortMultipartUpload");
        } else if (op == OP_GET) {
            //List multipart upload parts
            setAction("ListMultipartUploadParts");
        } else {
            fail_reason = "Bad action requested";
            return -1;
        }
        return 0;
    }

    // Handle everything else
    if (object_action) {
        op += DSS_KEYSTONE_MAX_ACTIONS;
    }
    setAction(ACTIONS[op]);
    return 0;
}

bool RGWResourceKeystoneInfo::get_bucket_public_perm(const string& action,
                                                     const string& resource,
                                                     bool& is_public_bucket,
                                                     string& reason) {
    // Public buckets not supported in Mar 31 release
    // Later change this with anon sign gen and verify ARL
    is_public_bucket = false;
    reason = "OK";
    return true;
}
