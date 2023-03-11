<!--
#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
-->

# Go Plugin APISIX Runner for Api gateway

Runs plugins written in Go. Implemented as a sidecar that accompanies APISIX.

## pack

```
cd cmd/go-runner && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" . && mv go-runner ../.. && cd ../..
```


### Attributes

| Name                 | Type   | Required | Default       | Description                                                                                  |
|----------------------|--------|----------|---------------|----------------------------------------------------------------------------------------------|
| token-key            | String | false    | Authorization | header头获取令牌key 或jwt数据                                                                        |
| mode                 | String | true     |               | 授权验证模式 jwt 或 customToken                                                                     |
| rbac                 | object | false    |               | rbac权限配置                                                                                     |
| rbac.state           | bool   | true     | false         | 是否开启rbac权限认证                                                                                 |
| rbac.key             | string | true     |               | rbac权限认证key值                                                                                 |
| rbac.value           | string | true     |               | rbac权限认证提取授权信息value键名                                                                        |
| rbac.linker          | string | false    |               | 获取rbac权限列表组合数据key名连接符                                                                        |
| jwt-auth             | object | false    |               | jwt配置                                                                                        |
| jwt-auth.secret      | string | true     |               | jwt  secret                                                                                  |
| jwt-auth.exp         | int    | true     |               | jwt 过期时间                                                                                     |
| jwt-auth.sso         | bool   | true     | false         | jwt 是否开启单点登录                                                                                 |
| jwt-auth.key         | string | false    |               | 单点登录redis key 单点登录开启必填 例如：jwt:sso:                                                           |
| jwt-auth.major-key   | string | true     |               | 单点登录登录态key值 结合jwt-auth.key获取登录态 例如：jwt-auth.major-key=user_id; user_id=123;则key为 jwt:sso:123 |
| redis-conf           | object | false    |               | redis配置 开启单点登录或rbac或自定义customToken必填                                                         |
| redis-conf.db        | int    | true     |               | 选择redis库                                                                                     |
| redis-conf.password  | string | false    |               | redis密码                                                                                      |
| redis-conf.hosts     | array  | true     |               | 主机（单主机链接） 暂不支持集群模式                                                                           |


## gp-authority jwt sso模式
```
setting plugin

curl "http://127.0.0.1:20000/apisix/admin/routes/1" \
-H "X-API-KEY: edd1c9w54233442336f8a8458785w" -X PUT -d '
{
"methods": ["GET"],
"host": "192.168.0.1",
"uri": "/admin/*",
"upstream_id": "1",
    "plugins": {
        "ext-plugin-pre-req": {
            "conf": [
                {"name":"gp-authority", "value":"{\"token-key\":\"Authorization\",\"mode\":\"jwt\",\"rbac\":{\"state\":false,\"key\":\"admin-rbac\",\"value\":\"user_id\",\"linker\":\":\"},\"jwt-auth\":{\"secret\":\"456gh245ww5426\",\"exp\":2592000,\"sso\":true,\"key\":\"sso:key:1250\",\"major-key\":\"userId\"},\"redis-conf\":{\"db\":1,\"password\":\"\",\"hosts\":[\"127.0.0.1:6379\"]}}"}
            ]
        }
    }
}'

require

curl -i -X GET "http://127.0.0.1:9080/admin/xxx/xxx" -H "Host: 192.168.0.1" -H "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2ODEwMzIzMDMsImlhdCI6MTY3ODQ0MDMwMywia2V5IjoidXNlciIsInVzZXJJZCI6MX0.0WrFZ8RC9TUGSDkl2S66GrKcbKXNfLeWCvb9OReSsy4"

```

## gp-authority customToken模式
```
setting plugin

curl "http://127.0.0.1:20000/apisix/admin/routes/1" \
-H "X-API-KEY: edd1c9w54233442336f8a8458785w" -X PUT -d '
{
"methods": ["GET"],
"host": "192.168.0.1",
"uri": "/admin/*",
"upstream_id": "1",
    "plugins": {
        "ext-plugin-pre-req": {
            "conf": [
                {"name":"gp-authority", "value":"{\"token-key\":\"token\",\"mode\":\"customToken\",\"rbac\":{\"state\":false,\"key\":\"admin-rbac\",\"value\":\"user_id\",\"linker\":\":\"},\"redis-conf\":{\"db\":1,\"password\":\"\",\"hosts\":[\"127.0.0.1:6379\"]}}"}
            ]
        }
    }
}'


request

curl -i -X GET "http://127.0.0.1:9080/admin/xxx/xxx" -H "Host: 192.168.0.1" -H "token: 989234i7iiuihjsd9889w32"
```


## License

Apache 2.0 LICENSE
