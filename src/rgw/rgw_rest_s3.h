// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#ifndef CEPH_RGW_REST_S3_H
#define CEPH_RGW_REST_S3_H
#define TIME_BUF_SIZE 128
#define RGW_AUTH_GRACE_MINS 15

#include "rgw_op.h"
#include "rgw_acl_s3.h"
#include "rgw_keystone.h"
#include "rgw_policy_s3.h"
#include "rgw_http_errors.h"

// For RGWResourceKeystoneInfo
#include "rgw_acl.h"
#include "rgw_rados.h"

void rgw_get_errno_s3(struct rgw_http_errors *e, int err_no);

class RGWGetObj_ObjStore_S3 : public RGWGetObj_ObjStore
{
protected:
  // Serving a custom error page from an object is really a 200 response with
  // just the status line altered.
  int custom_http_ret = 0;
public:
  RGWGetObj_ObjStore_S3() {}
  ~RGWGetObj_ObjStore_S3() {}

  int send_response_data_error();
  int send_response_data(bufferlist& bl, off_t ofs, off_t len);
  void set_custom_http_response(int http_ret) { custom_http_ret = http_ret; }
};

class RGWListBuckets_ObjStore_S3 : public RGWListBuckets_ObjStore {
public:
  RGWListBuckets_ObjStore_S3() {}
  ~RGWListBuckets_ObjStore_S3() {}

  int get_params() {
    limit = 0; /* no limit */
    return 0;
  }
  virtual void send_response_begin(bool has_buckets);
  virtual void send_response_data(RGWUserBuckets& buckets);
  virtual void send_response_end();
};

class RGWListBucket_ObjStore_S3 : public RGWListBucket_ObjStore {
public:
  RGWListBucket_ObjStore_S3() {
    default_max = 1000;
  }
  ~RGWListBucket_ObjStore_S3() {}

  int get_params();
  void send_response();
  void send_versioned_response();
};

class RGWGetBucketLogging_ObjStore_S3 : public RGWGetBucketLogging {
public:
  RGWGetBucketLogging_ObjStore_S3() {}
  ~RGWGetBucketLogging_ObjStore_S3() {}

  void send_response();
};

class RGWGetBucketLocation_ObjStore_S3 : public RGWGetBucketLocation {
public:
  RGWGetBucketLocation_ObjStore_S3() {}
  ~RGWGetBucketLocation_ObjStore_S3() {}

  void send_response();
};

class RGWGetBucketVersioning_ObjStore_S3 : public RGWGetBucketVersioning {
public:
  RGWGetBucketVersioning_ObjStore_S3() {}
  ~RGWGetBucketVersioning_ObjStore_S3() {}

  void send_response();
};

class RGWSetBucketVersioning_ObjStore_S3 : public RGWSetBucketVersioning {
public:
  RGWSetBucketVersioning_ObjStore_S3() {}
  ~RGWSetBucketVersioning_ObjStore_S3() {}

  int get_params();
  void send_response();
};

class RGWGetBucketWebsite_ObjStore_S3 : public RGWGetBucketWebsite {
public:
  RGWGetBucketWebsite_ObjStore_S3() {}
  ~RGWGetBucketWebsite_ObjStore_S3() {}

  void send_response();
};

class RGWSetBucketWebsite_ObjStore_S3 : public RGWSetBucketWebsite {
public:
  RGWSetBucketWebsite_ObjStore_S3() {}
  ~RGWSetBucketWebsite_ObjStore_S3() {}

  int get_params();
  void send_response();
};

class RGWDeleteBucketWebsite_ObjStore_S3 : public RGWDeleteBucketWebsite {
public:
  RGWDeleteBucketWebsite_ObjStore_S3() {}
  ~RGWDeleteBucketWebsite_ObjStore_S3() {}

  void send_response();
};

class RGWStatBucket_ObjStore_S3 : public RGWStatBucket_ObjStore {
public:
  RGWStatBucket_ObjStore_S3() {}
  ~RGWStatBucket_ObjStore_S3() {}

  void send_response();
};

class RGWCreateBucket_ObjStore_S3 : public RGWCreateBucket_ObjStore {
public:
  RGWCreateBucket_ObjStore_S3() {}
  ~RGWCreateBucket_ObjStore_S3() {}

  int get_params();
  void send_response();
};

class RGWDeleteBucket_ObjStore_S3 : public RGWDeleteBucket_ObjStore {
public:
  RGWDeleteBucket_ObjStore_S3() {}
  ~RGWDeleteBucket_ObjStore_S3() {}

  void send_response();
};

class RGWPutObj_ObjStore_S3 : public RGWPutObj_ObjStore {
public:
  RGWPutObj_ObjStore_S3() {}
  ~RGWPutObj_ObjStore_S3() {}

  int get_params();
  void send_response();
};

struct post_part_field {
  string val;
  map<string, string> params;
};

struct post_form_part {
  string name;
  string content_type;
  map<string, struct post_part_field, ltstr_nocase> fields;
  bufferlist data;
};

class RGWPostObj_ObjStore_S3 : public RGWPostObj_ObjStore {
  string boundary;
  string filename;
  bufferlist in_data;
  map<string, post_form_part, const ltstr_nocase> parts;
  RGWPolicyEnv env;
  RGWPolicy post_policy;
  string err_msg;

  int read_with_boundary(bufferlist& bl, uint64_t max, bool check_eol,
                         bool *reached_boundary,
			 bool *done);

  int read_line(bufferlist& bl, uint64_t max,
                bool *reached_boundary, bool *done);

  int read_data(bufferlist& bl, uint64_t max, bool *reached_boundary, bool *done);

  int read_form_part_header(struct post_form_part *part,
                            bool *done);
  bool part_str(const string& name, string *val);
  bool part_bl(const string& name, bufferlist *pbl);

  int get_policy();
  void rebuild_key(string& key);
public:
  RGWPostObj_ObjStore_S3() {}
  ~RGWPostObj_ObjStore_S3() {}

  int get_params();
  int complete_get_params();
  void send_response();
  int get_data(bufferlist& bl,MD5* hash= NULL);
};

class RGWDeleteObj_ObjStore_S3 : public RGWDeleteObj_ObjStore {
public:
  RGWDeleteObj_ObjStore_S3() {}
  ~RGWDeleteObj_ObjStore_S3() {}

  void send_response();
};

class RGWCopyObj_ObjStore_S3 : public RGWCopyObj_ObjStore {
  bool sent_header;
public:
  RGWCopyObj_ObjStore_S3() : sent_header(false) {}
  ~RGWCopyObj_ObjStore_S3() {}

  int init_dest_policy();
  int get_params();
  void send_partial_response(off_t ofs);
  void send_response();
};

class RGWRenameObj_ObjStore_S3 : public RGWRenameObj_ObjStore {
    public:
        RGWRenameObj_ObjStore_S3() {}
        ~RGWRenameObj_ObjStore_S3() {}

        void send_response();
};

class RGWGetACLs_ObjStore_S3 : public RGWGetACLs_ObjStore {
public:
  RGWGetACLs_ObjStore_S3() {}
  ~RGWGetACLs_ObjStore_S3() {}

  void send_response();
};

class RGWPutACLs_ObjStore_S3 : public RGWPutACLs_ObjStore {
public:
  RGWPutACLs_ObjStore_S3() {}
  ~RGWPutACLs_ObjStore_S3() {}

  int get_policy_from_state(RGWRados *store, struct req_state *s, stringstream& ss);
  void send_response();
};

class RGWGetCORS_ObjStore_S3 : public RGWGetCORS_ObjStore {
public:
  RGWGetCORS_ObjStore_S3() {}
  ~RGWGetCORS_ObjStore_S3() {}

  void send_response();
};

class RGWPutCORS_ObjStore_S3 : public RGWPutCORS_ObjStore {
public:
  RGWPutCORS_ObjStore_S3() {}
  ~RGWPutCORS_ObjStore_S3() {}

  int get_params();
  void send_response();
};

class RGWDeleteCORS_ObjStore_S3 : public RGWDeleteCORS_ObjStore {
public:
  RGWDeleteCORS_ObjStore_S3() {}
  ~RGWDeleteCORS_ObjStore_S3() {}

  void send_response();
};

class RGWOptionsCORS_ObjStore_S3 : public RGWOptionsCORS_ObjStore {
public:
  RGWOptionsCORS_ObjStore_S3() {}
  ~RGWOptionsCORS_ObjStore_S3() {}

  void send_response();
};

class RGWInitMultipart_ObjStore_S3 : public RGWInitMultipart_ObjStore {
public:
  RGWInitMultipart_ObjStore_S3() {}
  ~RGWInitMultipart_ObjStore_S3() {}

  int get_params();
  void send_response();
};

class RGWCompleteMultipart_ObjStore_S3 : public RGWCompleteMultipart_ObjStore {
public:
  RGWCompleteMultipart_ObjStore_S3() {}
  ~RGWCompleteMultipart_ObjStore_S3() {}

  void send_response();
};

class RGWAbortMultipart_ObjStore_S3 : public RGWAbortMultipart_ObjStore {
public:
  RGWAbortMultipart_ObjStore_S3() {}
  ~RGWAbortMultipart_ObjStore_S3() {}

  void send_response();
};

class RGWListMultipart_ObjStore_S3 : public RGWListMultipart_ObjStore {
public:
  RGWListMultipart_ObjStore_S3() {}
  ~RGWListMultipart_ObjStore_S3() {}

  void send_response();
};

class RGWListBucketMultiparts_ObjStore_S3 : public RGWListBucketMultiparts_ObjStore {
public:
  RGWListBucketMultiparts_ObjStore_S3() {
    default_max = 1000;
  }
  ~RGWListBucketMultiparts_ObjStore_S3() {}

  void send_response();
};

class RGWDeleteMultiObj_ObjStore_S3 : public RGWDeleteMultiObj_ObjStore {
public:
  RGWDeleteMultiObj_ObjStore_S3() {}
  ~RGWDeleteMultiObj_ObjStore_S3() {}

  void send_status();
  void begin_response();
  void send_partial_response(rgw_obj_key& key, bool delete_marker,
                             const string& marker_version_id, int ret);
  void end_response();
};

class RGW_Auth_S3_Keystone_ValidateToken : public RGWHTTPClient {
private:
  bufferlist rx_buffer;
  bufferlist rx_headers_buffer;
  bufferlist tx_buffer;
  bufferlist::iterator tx_buffer_it;
  list<string> roles_list;

public:
  KeystoneToken response;

private:
  void set_tx_buffer(const string& d) {
    tx_buffer.clear();
    tx_buffer.append(d);
    tx_buffer_it = tx_buffer.begin();
    set_send_length(tx_buffer.length());
  }

public:
  RGW_Auth_S3_Keystone_ValidateToken(CephContext *_cct)
      : RGWHTTPClient(_cct) {
    get_str_list(cct->_conf->rgw_keystone_accepted_roles, roles_list);
  }

  int receive_header(void *ptr, size_t len) {
    rx_headers_buffer.append((char *)ptr, len);
    return 0;
  }
  int receive_data(void *ptr, size_t len) {
    rx_buffer.append((char *)ptr, len);
    return 0;
  }

  int send_data(void *ptr, size_t len) {
    if (!tx_buffer_it.get_remaining())
      return 0; // nothing left to send

    int l = MIN(tx_buffer_it.get_remaining(), len);
    memcpy(ptr, tx_buffer_it.get_current_ptr().c_str(), l);
    try {
      tx_buffer_it.advance(l);
    } catch (buffer::end_of_buffer &e) {
      assert(0);
    }

    return l;
  }

  int validate_request(const string& action,
                       const string& resource_name,
                       const string& tenant_name,
                       const string& source_ip,
                       const bool&   is_sign_auth,
                       const bool&   is_copy,
                       const bool&   is_cross_account,
                       const bool&   is_url_token,
                       const bool&   is_infini_url_token,
                       const string& copy_src,
                       const string& token,
                       const string& auth_id,
                       const string& auth_token,
                       const string& auth_sign,
                       const string& objectname,
                       string& iamerror);

  int make_iam_request(const string& keystone_url,
                             string& iamerror,
                       const string& rootAccount,
                       const bool& is_infini_url_token);
};

class RGW_Auth_S3 {
public:
  static int authorize(RGWRados *store, struct req_state *s);
};

class RGWHandler_Auth_S3 : public RGWHandler_ObjStore {
  friend class RGWRESTMgr_S3;
public:
  RGWHandler_Auth_S3() : RGWHandler_ObjStore() {}
  virtual ~RGWHandler_Auth_S3() {}

  virtual int validate_bucket_name(const string& bucket, int name_strictness) {
    return 0;
  }

  virtual int validate_object_name(const string& bucket) { return 0; }

  virtual int init(RGWRados *store, struct req_state *state, RGWClientIO *cio);
  virtual int authorize() {
    return RGW_Auth_S3::authorize(store, s);
  }
};

class RGWHandler_ObjStore_S3 : public RGWHandler_ObjStore {
  friend class RGWRESTMgr_S3;
public:
  static int init_from_header(struct req_state *s, int default_formatter, bool configurable_format);

  RGWHandler_ObjStore_S3() : RGWHandler_ObjStore() {}
  virtual ~RGWHandler_ObjStore_S3() {}

  int validate_bucket_name(const string& bucket, int name_strictness);

  virtual int init(RGWRados *store, struct req_state *state, RGWClientIO *cio);
  virtual int authorize() {
    return RGW_Auth_S3::authorize(store, s);
  }
  virtual int retarget(RGWOp *op, RGWOp **new_op) {
    *new_op = op;
    return 0;
  }
};

class RGWHandler_ObjStore_Service_S3 : public RGWHandler_ObjStore_S3 {
protected:
  RGWOp *op_get();
  RGWOp *op_head();
public:
  RGWHandler_ObjStore_Service_S3() {}
  virtual ~RGWHandler_ObjStore_Service_S3() {}
};

class RGWHandler_ObjStore_Bucket_S3 : public RGWHandler_ObjStore_S3 {
protected:
  bool is_acl_op() {
    return s->info.args.exists("acl");
  }
  bool is_cors_op() {
      return s->info.args.exists("cors");
  }
  bool is_obj_update_op() {
    return is_acl_op() || is_cors_op();
  }
  RGWOp *get_obj_op(bool get_data);

  RGWOp *op_get();
  RGWOp *op_head();
  RGWOp *op_put();
  RGWOp *op_delete();
  RGWOp *op_post();
  RGWOp *op_options();
public:
  RGWHandler_ObjStore_Bucket_S3() {}
  virtual ~RGWHandler_ObjStore_Bucket_S3() {}
};

class RGWHandler_ObjStore_Obj_S3 : public RGWHandler_ObjStore_S3 {
protected:
  bool is_acl_op() {
    return s->info.args.exists("acl");
  }
  bool is_cors_op() {
      return s->info.args.exists("cors");
  }
  bool is_obj_update_op() {
    return is_acl_op();
  }
  bool is_rename_op() {
      return s->info.args.exists("newname");
  }
  RGWOp *get_obj_op(bool get_data);

  RGWOp *op_get();
  RGWOp *op_head();
  RGWOp *op_put();
  RGWOp *op_delete();
  RGWOp *op_post();
  RGWOp *op_options();
public:
  RGWHandler_ObjStore_Obj_S3() {}
  virtual ~RGWHandler_ObjStore_Obj_S3() {}
};

class RGWRESTMgr_S3 : public RGWRESTMgr {
private:
  bool enable_s3website;
public:
  RGWRESTMgr_S3(bool enable_s3website) : enable_s3website(false) { this->enable_s3website = enable_s3website; }
  virtual ~RGWRESTMgr_S3() {}

  virtual RGWRESTMgr *get_resource_mgr(struct req_state *s, const string& uri) {
    return this;
  }
  virtual RGWHandler *get_handler(struct req_state *s);
};

#define DSS_KEYSTONE_MAX_ACTIONS 7
class RGWResourceKeystoneInfo {
    private:
        string _tenant_name;
        string _resource_name;
        string _action;
        string _object_name;
        struct req_state* _s;
        RGWRados*  _store;
        bool _copy_req;
        string _copy_src;

        // Based on Enum http_op in rgw_common.h
        const string ACTIONS[2 * DSS_KEYSTONE_MAX_ACTIONS] = {
            "ListBucket",
            "CreateBucket",
            "DeleteBucket",
            "HeadBucket",     // Permission same as Get
            "PostBucket",     // Not supported but needed
            "CopyBucket",     // Not supported but needed
            "OptionsBucket",  // Not supported but needed
            "GetObject",
            "PutObject",
            "DeleteObject",
            "HeadObject",     // Permission same as Get
            "PostObject",
            "CopyObject",     // Handled differently. Needed.
            "OptionsObject"   // Not supported but needed
        };

    public:
        RGWResourceKeystoneInfo(struct req_state *s, RGWRados *store, bool copyAction) :
            _s(s), _store(store), _copy_req(copyAction) { }
        RGWResourceKeystoneInfo() : _s(NULL), _store(NULL), _copy_req(false) { }
        ~RGWResourceKeystoneInfo() { }

        inline string getTenantName()
        {
            return _tenant_name;
        }
        inline string getResourceName()
        {
            return _resource_name;
        }
        inline string getAction()
        {
            return _action;
        }
        inline void setTenantName(string& tenant_name)
        {
            _tenant_name = tenant_name;
        }
        inline void setResourceName(string& resource_name)
        {
            _resource_name = resource_name;
        }
        inline void setAction(const string& action)
        {
            _action = action;
        }
        inline bool getCopyAction()
        {
            return _copy_req;
        }
        inline void setCopyAction(bool action)
        {
            _copy_req = action;
        }
        inline string getCopySrc()
        {
            return _copy_src;
        }
        inline void setCopySrc(string& cpysrc)
        {
            _copy_src = cpysrc;
        }
        inline string getObjectName()
        {
            return _object_name;
        }
        inline void setObjectName(string& val)
        {
            _object_name = val;
        }

        enum specialActions {
            _none = 0,
            _list_all_buckets,
            _multipart_upload,
            _multipart_id_action,
            _copy_action
        };

        uint32_t fetchInfo(string& fail_reason);
        uint32_t fetchActionString(uint32_t op,
                                   bool object_action,
                                   int special_action,
                                   string& fail_reason);

        bool get_bucket_public_perm(const string& action,
                                    const string& resource,
                                    bool& is_public_bucket,
                                    string& reason);
};

class RGW_KMS: public RGWHTTPClient {
private:
  bufferlist rx_buffer;
  bufferlist rx_headers_buffer;
  bufferlist tx_buffer;
  bufferlist::iterator tx_buffer_it;

private:
  void set_tx_buffer(const string& d) {
    tx_buffer.clear();
    tx_buffer.append(d);
    tx_buffer_it = tx_buffer.begin();
    set_send_length(tx_buffer.length());
  }

public:
  RGW_KMS(CephContext *_cct)
      : RGWHTTPClient(_cct) {
  }

  int receive_header(void *ptr, size_t len) {
    rx_headers_buffer.append((char *)ptr, len);
    return 0;
  }
  int receive_data(void *ptr, size_t len) {
    rx_buffer.append((char *)ptr, len);
    return 0;
  }

  int send_data(void *ptr, size_t len) {
    if (!tx_buffer_it.get_remaining())
      return 0; // nothing left to send

    int l = MIN(tx_buffer_it.get_remaining(), len);
    memcpy(ptr, tx_buffer_it.get_current_ptr().c_str(), l);
    try {
      tx_buffer_it.advance(l);
    } catch (buffer::end_of_buffer &e) {
      assert(0);
    }

    return l;
  }

  int make_kms_encrypt_request(string &root_acount, RGWKmsData* kmsdata);
  int make_kms_decrypt_request(string &root_acount, RGWKmsData* kmsdata);;

};


class dss_endpoint {
    public:
        static string endpoint;
        dss_endpoint() { }
        ~dss_endpoint() { }
};
class RGWHandler_ObjStore_Obj_S3Website;

#endif
