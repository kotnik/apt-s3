#include <curl/curl.h>
#include <sstream>
#include <iostream>
#include <string>
#include <jsoncpp/json/json.h>

#include "roles.h"

using namespace std;

static size_t data_write(void* buf, size_t size, size_t nmemb, void* userp)
{
  if(userp)
  {
    ostream& os = *static_cast<ostream*>(userp);
    streamsize len = size * nmemb;
    if(os.write(static_cast<char*>(buf), len))
      return len;
  }

  return 0;
}

/**
 * timeout is in seconds
 **/
CURLcode curl_read(const string& url, ostream& os, long timeout = 30)

{
  CURLcode code(CURLE_FAILED_INIT);
  CURL* curl = curl_easy_init();

  if(curl)
  {
    if(CURLE_OK == (code = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &data_write))
    && CURLE_OK == (code = curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L))
    && CURLE_OK == (code = curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L))
    && CURLE_OK == (code = curl_easy_setopt(curl, CURLOPT_FILE, &os))
    && CURLE_OK == (code = curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout))
    && CURLE_OK == (code = curl_easy_setopt(curl, CURLOPT_URL, url.c_str())))
    {
      code = curl_easy_perform(curl);
    }
    curl_easy_cleanup(curl);
  }
  return code;
}

bool GetRoleData(string &access_key, string &secret_key, string &token) {
  curl_global_init(CURL_GLOBAL_ALL);

  ostringstream oss;
  string url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/";
  bool success = false;
  if(CURLE_OK == curl_read(url.c_str(), oss))
  {
    string role = oss.str();
    string role_url = url + role + "/";
    ostringstream result;
    if (CURLE_OK == curl_read(role_url.c_str(), result)) {
      string json = result.str();
      Json::Value root;
      Json::Reader reader;
      bool parsingSuccessful = reader.parse(json, root);
      if (parsingSuccessful) {
        access_key = root.get("AccessKeyId", "").asString();
        secret_key = root.get("SecretAccessKey", "").asString();
        token = root.get("Token", "").asString();
        success = true;
      }
    }
  }
  curl_global_cleanup();
  return success; 
}
