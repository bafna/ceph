// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#ifndef RGW_HTTP_ERRORS_H_
#define RGW_HTTP_ERRORS_H_

#include "rgw_common.h"

struct rgw_http_errors {
  int err_no;
  int http_ret;
  const char *s3_code;
  const char *s3_err_message;
};

const static struct rgw_http_errors RGW_HTTP_ERRORS[] = {
    { 0, 200, "" },
    { STATUS_CREATED, 201, "Created" },
    { STATUS_ACCEPTED, 202, "Accepted" },
    { STATUS_NO_CONTENT, 204, "NoContent", "There was no need to send any content with this type of request" },
    { STATUS_PARTIAL_CONTENT, 206, "" },
    { ERR_PERMANENT_REDIRECT, 301, "PermanentRedirect" },
    { ERR_WEBSITE_REDIRECT, 301, "WebsiteRedirect" },
    { STATUS_REDIRECT, 303, "" },
    { ERR_NOT_MODIFIED, 304, "NotModified" },
    { EINVAL, 400, "InvalidArgument", "Invalid Argument"},
    { ERR_INVALID_REQUEST, 400, "InvalidRequest" },
    { ERR_INVALID_DIGEST, 400, "InvalidDigest" },
    { ERR_BAD_DIGEST, 400, "BadDigest" },
    { ERR_INVALID_BUCKET_NAME, 400, "InvalidBucketName", "The specified bucket name is not valid."},
    { ERR_INVALID_OBJECT_NAME, 400, "InvalidObjectName" , "The specified object name exceeds the maximum allowed character size of 1024 chars."},
    { ERR_UNRESOLVABLE_EMAIL, 400, "UnresolvableGrantByEmailAddress" },
    { ERR_INVALID_PART, 400, "InvalidPart", "One or more of the specified parts could not be found. The part might not have been uploaded, or the specified entity tag might not have matched the part's entity tag."},
    { ERR_INVALID_PART_ORDER, 400, "InvalidPartOrder" },
    { ERR_REQUEST_TIMEOUT, 400, "RequestTimeout", "Your socket connection to the server was not read from or written to within the timeout period." },
    { ERR_TOO_LARGE, 400, "EntityTooLarge", "Your proposed upload exceeds the maximum allowed object size (5GB in our case)."},
    { ERR_TOO_SMALL, 400, "EntityTooSmall", "Your proposed upload is smaller than the minimum allowed size (1 MB in our case for multipart upload)"},
    { ERR_TOO_MANY_BUCKETS, 400, "TooManyBuckets" , "You have attempted to create more buckets than allowed"},
    {ERR_BUCKET_ALREADY_OWNED, 409, "BucketAlreadyOwnedByYou" , "Your previous request to create the named bucket succeeded and you already own it."},
    //{ ERR_MALFORMED_XML, 400, "MalformedXML" },
    { ERR_LENGTH_REQUIRED, 411, "MissingContentLength", "You must provide the Content-Length HTTP header."},
    { EACCES, 403, "AccessDenied", "Access Denied"},
    { EPERM, 403, "AccessDenied", "Access Denied"},
    { ERR_SIGNATURE_NO_MATCH, 403, "SignatureDoesNotMatch", "The request signature we calculated does not match the signature you provided."},
    { ERR_INVALID_ACCESS_KEY, 403, "AccessDenied", "The access key Id you provided does not exist in our records."},
    { ERR_USER_SUSPENDED, 403, "UserSuspended" },
    { ERR_REQUEST_TIME_SKEWED, 403, "RequestTimeTooSkewed" ,"The difference between the request time and the server's time is too large."},
    { ERR_QUOTA_EXCEEDED, 403, "QuotaExceeded" },
    { ERR_BAD_RENAME_REQ, 403, "BadRenameRequest", "Rename request must have object name, new object name and the HTTP method should be PUT."},
    { ERR_RENAME_NOT_ENABLED, 403, "RenameDisabled", "Rename operation is not enabled"},
    { ERR_RENAME_FAILED, 403, "RenameFailed", "Rename operation has failed."},
    { ERR_RENAME_OBJ_EXISTS, 403, "ObjectExists", "Rename operation cannot continue as the target object already exists."},
    { ENOENT, 404, "NoSuchKey", "Resource not found."},
    { ERR_NO_SUCH_BUCKET, 404, "NoSuchBucket", "Resource not found"},
    { ERR_NO_SUCH_UPLOAD, 404, "NoSuchUpload", "The specified multipart upload does not exist. The upload ID might be invalid, or the multipart upload might have been aborted or completed."},
    { ERR_NOT_FOUND, 404, "Not Found", "Resource not found"},
    { ERR_METHOD_NOT_ALLOWED, 405, "MethodNotAllowed", "The specified method is not allowed against this resource."},
    { ETIMEDOUT, 408, "RequestTimeout", "Your socket connection to the server was not read from or written to within the timeout period."},
    { EEXIST, 409, "BucketAlreadyExists", "The requested bucket name is not available. Please select a different name and try again"},
    { ENOTEMPTY, 409, "BucketNotEmpty", "The bucket you tried to delete is not empty"},
    { ERR_NO_SUCH_WEBSITE_CONFIGURATION, 404, "NoSuchWebsiteConfiguration" },
    { ERR_USER_EXIST, 409, "UserAlreadyExists" },
    { ERR_PRECONDITION_FAILED, 412, "PreconditionFailed" },
    { ERANGE, 416, "InvalidRange", "The requested range cannot be satisfied."},
    { ERR_UNPROCESSABLE_ENTITY, 422, "UnprocessableEntity" },
    { ERR_LOCKED, 423, "Locked" },
    { ERR_INTERNAL_ERROR, 500, "InternalError", "We encountered an internal error. Please try again." },
    { ERR_RENAME_COPY_FAILED, 500, "RenameFailed", "Object copy failed during rename. Please file a bug." },
    { ERR_RENAME_DATA_LOST, 500, "DataLost", "Rename operation lost the original data. Please file a bug." },
    { ERR_RENAME_NEW_OBJ_DEL_FAILED, 500, "RenameFailed", "Rename operation failed. Please delete the duplicated object with name same as new name for the object, manually. Please file a bug." },
    {ERR_INVALID_ENC_ALGO, 400, "InvalidEncryptionAlgorithmError", "The encryption request you specified is not valid. The valid value is AES256." },
};

const static struct rgw_http_errors RGW_HTTP_SWIFT_ERRORS[] = {
    { EACCES, 401, "AccessDenied" },
    { EPERM, 401, "AccessDenied" },
    { ERR_USER_SUSPENDED, 401, "UserSuspended" },
    { ERR_INVALID_UTF8, 412, "Invalid UTF8" },
    { ERR_BAD_URL, 412, "Bad URL" },
};

struct rgw_http_status_code {
  int code;
  const char *name;
};

const static struct rgw_http_status_code http_codes[] = {
  { 100, "Continue" },
  { 200, "OK" },
  { 201, "Created" },
  { 202, "Accepted" },
  { 204, "No Content" },
  { 205, "Reset Content" },
  { 206, "Partial Content" },
  { 207, "Multi Status" },
  { 208, "Already Reported" },
  { 300, "Multiple Choices" },
  { 301, "Moved Permanently" },
  { 302, "Found" },
  { 303, "See Other" },
  { 304, "Not Modified" },
  { 305, "User Proxy" },
  { 306, "Switch Proxy" },
  { 307, "Temporary Redirect" },
  { 308, "Permanent Redirect" },
  { 400, "Bad Request" },
  { 401, "Unauthorized" },
  { 402, "Payment Required" },
  { 403, "Forbidden" },
  { 404, "Not Found" },
  { 405, "Method Not Allowed" },
  { 406, "Not Acceptable" },
  { 407, "Proxy Authentication Required" },
  { 408, "Request Timeout" },
  { 409, "Conflict" },
  { 410, "Gone" },
  { 411, "Length Required" },
  { 412, "Precondition Failed" },
  { 413, "Request Entity Too Large" },
  { 414, "Request-URI Too Long" },
  { 415, "Unsupported Media Type" },
  { 416, "Requested Range Not Satisfiable" },
  { 417, "Expectation Failed" },
  { 422, "Unprocessable Entity" },
  { 500, "Internal Server Error" },
  { 0, NULL },
};

#define ARRAY_LEN(arr) (sizeof(arr) / sizeof(arr[0]))

static inline const struct rgw_http_errors *search_err(int err_no, const struct rgw_http_errors *errs, int len)
{
  for (int i = 0; i < len; ++i, ++errs) {
    if (err_no == errs->err_no)
      return errs;
  }
  return NULL;
}


static inline int rgw_http_error_to_errno(int http_err)
{
  if (http_err >= 200 && http_err <= 299)
    return 0;
  switch (http_err) {
    case 400:
      return -EINVAL;
    case 401:
      return -EPERM;
    case 403:
        return -EACCES;
    case 404:
        return -ENOENT;
    default:
        return -EIO;
  }

  return 0; /* unreachable */
}


#endif
