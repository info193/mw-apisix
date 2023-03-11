/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package plugins

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	pkgHTTP "github.com/apache/apisix-go-plugin-runner/pkg/http"
	"github.com/apache/apisix-go-plugin-runner/pkg/log"
	"github.com/apache/apisix-go-plugin-runner/pkg/plugin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/redis/go-redis/v9"
	"net/http"
	"strings"
	"time"
)

func init() {
	err := plugin.RegisterPlugin(&GPAuthority{})
	if err != nil {
		log.Fatalf("failed to register plugin gp-authority: %s", err)
	}
}

// GPAuthority is a demo to show how to return data directly instead of proxying
// it to the upstream.
type GPAuthority struct {
	// Embed the default plugin here,
	// so that we don't need to reimplement all the methods.
	plugin.DefaultPlugin
	redis           *redis.Client
	GPAuthorityConf GPAuthorityConf
}
type JwtConf struct {
	Secret    string `json:"secret"`
	Algorithm string `json:"algorithm"`
	Exp       int64  `json:"exp"`
	Sso       bool   `json:"sso"`
	Key       string `json:"key"`
	MajorKey  string `json:"major-key"`
}
type RedisConf struct {
	DB       int      `json:"db"`
	Password string   `json:"password"`
	Hosts    []string `json:"hosts"`
}
type Rbac struct {
	State  bool   `json:"state"`
	Key    string `json:"key"`
	Value  string `json:"value"`
	Linker string `json:"linker"`
}
type Response struct {
	Code int64       `json:"code"`
	Msg  string      `json:"msg"`
	Data interface{} `json:"data"`
}

type GPAuthorityConf struct {
	TokenKey  string    `json:"token-key"`
	Mode      string    `json:"mode"` // jwt、customToken
	Rbac      Rbac      `json:"rbac"`
	JwtAuth   JwtConf   `json:"jwt-auth"`
	RedisConf RedisConf `json:"redis-conf"`
}

func (p *GPAuthority) Name() string {
	return "gp-authority"
}

func (p *GPAuthority) ParseConf(in []byte) (interface{}, error) {
	conf := GPAuthorityConf{}
	err := json.Unmarshal(in, &conf)
	p.GPAuthorityConf = conf
	return conf, err
}
func (p *GPAuthority) ParseJwtConf(in []byte) (JwtConf, error) {
	conf := JwtConf{}
	err := json.Unmarshal(in, &conf)
	return conf, err
}

// 单节点
func newRedis(RedisConf RedisConf) *redis.Client {
	if len(RedisConf.Hosts) <= 0 {
		return nil
	}
	return redis.NewClient(&redis.Options{
		DB:       RedisConf.DB,
		Password: RedisConf.Password,
		Addr:     RedisConf.Hosts[0],
	})
}

// 判断是否登录
func (p *GPAuthority) TokenAuthorize(key string) (map[string]interface{}, error) {
	if p.GPAuthorityConf.Mode != "customToken" {
		return nil, nil
	}
	// jwt 参数或配置有误
	if (p.GPAuthorityConf.Mode == "customToken" && p.GPAuthorityConf.TokenKey == "") || key == "" {
		return nil, errors.New("Account authorization key must exist")
	}

	ctx := context.Background()
	user := make(map[string]interface{}, 0)
	token := p.redis.Get(ctx, key).Val()
	if token == "" {
		return nil, errors.New("Account not logged in or not authorized")
	}

	if p.GPAuthorityConf.Rbac.Value == "" {
		user["user_id"] = token
		return user, nil
	}

	err := json.Unmarshal([]byte(token), &user)
	if err != nil {
		log.Errorf("gp-authority 解析数据失败 err=%s", err)
		return nil, err
	}

	return user, nil
}
func (p *GPAuthority) JwtAuthorize(key string) (map[string]interface{}, error) {
	if p.GPAuthorityConf.Mode != "jwt" {
		return nil, nil
	}
	// jwt 参数或配置有误
	if (p.GPAuthorityConf.Mode == "jwt" && p.GPAuthorityConf.JwtAuth.Secret == "") || key == "" {
		return nil, errors.New("jwt token key param")
	}

	user := make(map[string]interface{}, 0)
	token, err := jwt.Parse(key, func(t *jwt.Token) (interface{}, error) {
		return []byte(p.GPAuthorityConf.JwtAuth.Secret), nil
	})
	if err != nil {
		return nil, err
	}

	// 检测jwt是否过期
	if !token.Valid {
		return nil, errors.New("jwt token valid error")
	}
	if expTime, ok := token.Claims.(jwt.MapClaims)["exp"].(float64); ok {
		exp := time.Unix(int64(expTime), 0)
		remainder := exp.Sub(time.Now().Local())
		if remainder <= 0 {
			return nil, errors.New("jwt token lose efficacy")
		}
	}

	var userId string
	if tempId, ok := token.Claims.(jwt.MapClaims)[p.GPAuthorityConf.JwtAuth.MajorKey].(float64); ok {
		userId = p.FmtStrFromInterface(tempId)
		user["user_id"] = userId
	}

	// 检测是否单点登录
	if p.GPAuthorityConf.JwtAuth.Sso && p.GPAuthorityConf.JwtAuth.MajorKey != "" && p.GPAuthorityConf.JwtAuth.Key != "" {
		ctx := context.Background()
		redisKey := fmt.Sprintf("%s%s", p.GPAuthorityConf.JwtAuth.Key, userId)
		exists := p.redis.Get(ctx, redisKey).Val()
		//log.Errorf("failed to ---------: %s -======%s====%s-==exists:%s.....", err, redisKey, userId, exists)
		if exists == "" {
			return nil, errors.New("jwt token login expire")
		}
	}

	return user, nil
}
func (p *GPAuthority) FmtStrFromInterface(val interface{}) string {
	if val == nil {
		return ""
	}
	switch ret := val.(type) {
	case string:
		return ret
	case int8, uint8, int16, uint16, int, uint, int64, uint64, float32, float64:
		return fmt.Sprintf("%v", ret)
	}
	return ""
}
func (p *GPAuthority) permission(user map[string]interface{}, path string) error {
	ctx := context.Background()

	rbacKey := fmt.Sprintf("%s", p.GPAuthorityConf.Rbac.Key)
	if p.GPAuthorityConf.Rbac.Value != "" {
		if _, ok := user[p.GPAuthorityConf.Rbac.Value]; ok {
			rbacKey = fmt.Sprintf("%s%s%s", p.GPAuthorityConf.Rbac.Key, p.GPAuthorityConf.Rbac.Linker, p.FmtStrFromInterface(user[p.GPAuthorityConf.Rbac.Value]))
		}
	}
	if _, ok := user["user_id"]; ok && p.GPAuthorityConf.Rbac.Value == "" {
		rbacKey = fmt.Sprintf("%s%s%s", p.GPAuthorityConf.Rbac.Key, p.GPAuthorityConf.Rbac.Linker, p.FmtStrFromInterface(user["user_id"]))
	}

	token := p.redis.Get(ctx, rbacKey).Val()
	if token == "" {
		log.Errorf("gp-authority 权限验证获取权限数据不存在")
		return errors.New("invalid rbacKey data empty")
	}
	permiss := make(map[string]int64, 0)
	err := json.Unmarshal([]byte(token), &permiss)
	if err != nil {
		log.Errorf("gp-authority 权限数据解析失败 err=%s", err)
		return errors.New("invalid rbac data analysis error")
	}
	pathName := strings.Trim(path, "/")
	if _, ok := permiss[pathName]; !ok {
		return errors.New("No permission")
	}

	return nil
}

func (p *GPAuthority) RequestFilter(conf interface{}, w http.ResponseWriter, r pkgHTTP.Request) {
	redisConf := conf.(GPAuthorityConf).RedisConf
	p.redis = newRedis(redisConf)
	// 开启单点登录、或权限验证必须配置redis
	if (p.GPAuthorityConf.JwtAuth.Sso || p.GPAuthorityConf.Rbac.State) && p.redis == nil {
		resp, _ := json.Marshal(Response{Code: 400, Msg: "环境配置错误", Data: nil})
		_, err := w.Write(resp)
		if err != nil {
			log.Errorf("failed to write: %s -======%s", err)
		}
		return
	}

	var headerKey string
	headerKey = r.Header().Get("Authorization")
	if p.GPAuthorityConf.TokenKey != "" {
		headerKey = r.Header().Get(p.GPAuthorityConf.TokenKey)
	}

	r.Header().Set("X-Rbac", "api demo")
	user, err := p.JwtAuthorize(headerKey)
	if err != nil {
		log.Errorf("failed to ---------: %s -======%s", err)

		resp, _ := json.Marshal(Response{Code: 401, Msg: "未登录或账号未授权", Data: nil})
		_, err := w.Write(resp)
		if err != nil {
			log.Errorf("failed to write: %s -======%s", err)
		}
		return
	}

	// 检测是否登录token授权
	user, err = p.TokenAuthorize(headerKey)
	if err != nil {
		resp, _ := json.Marshal(Response{Code: 401, Msg: "未登录或账号未授权", Data: nil})
		_, err := w.Write(resp)
		if err != nil {
			log.Errorf("failed to write: %s -======%s", err)
		}
		return
	}
	//log.Errorf("----------------------------%s-------headerKey：%s", user, headerKey)
	// 权限验证 rbac key存在必须验证
	if p.GPAuthorityConf.Rbac.State && p.GPAuthorityConf.Rbac.Key != "" {
		if err := p.permission(user, string(r.Path())); err != nil {
			resp, _ := json.Marshal(Response{Code: 402, Msg: "暂无权限", Data: nil})
			_, err := w.Write(resp)
			if err != nil {
				log.Errorf("failed to write: %s -======%s", err)
			}
			return
		}
	}
}

//func (p *GPAuthority) ResponseFilter(conf interface{}, r pkgHTTP.Response) {
//	body, _ := r.ReadBody()
//	statusCode := r.StatusCode()
//	header := r.Header()
//	log.Errorf("Response to ----------body: %s,statusCode：%s，header：%s", body, statusCode, header)

//Authorization := r.Header().Get("Authorization")
//token, _ := jwt.Parse(Authorization, func(t *jwt.Token) (interface{}, error) {
//	return []byte(jwtAuth.Secret), nil
//})
//
//log.Errorf("11111111------------jwtConf: %s,,,,,body:%s,,,,%s,,,,,,,,,,,", jwtAuth, Authorization, r.Header())
//log.Errorf("22222222------------jwtConf: %s,,,,,token:%s,,,,%s,,,,,,,,,,,%s", jwtAuth, token, Authorization, r.Header())
//log.Errorf("解析jwt------------userId: %s,,,,,exp:%s,,,,iat:%s......../././.redisConf:%s", token.Claims.(jwt.MapClaims)["userId"], token.Claims.(jwt.MapClaims)["exp"], token.Claims.(jwt.MapClaims)["iat"], redisConf)

//log.Errorf("failed to ----------: %s", w.Header())
//r.RespHeader().Del("Server")
//}
