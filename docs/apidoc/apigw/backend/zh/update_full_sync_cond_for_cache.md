### 描述

更新全量同步缓存条件信息(版本: v3.14.1+，权限: 全量同步缓存条件的更新权限)

### 输入参数

| 参数名称 | 参数类型   | 必选 | 描述               |
|------|--------|----|------------------|
| id   | int    | 是  | 需要更新的全量同步缓存条件的ID |
| data | object | 是  | 需要更新的全量同步缓存条件的数据 |

#### data

| 参数名称     | 参数类型 | 必选 | 描述                                  |
|----------|------|----|-------------------------------------|
| interval | int  | 是  | 同步周期，单位为小时，用于指定缓存的过期时间，最短为6小时，最长为7天 |

### 调用示例

```json
{
  "id": 123,
  "data": {
    "interval": 24
  }
}
```

### 响应示例

```json
{
  "result": true,
  "code": 0,
  "message": "success",
  "permission": null,
  "data": null
}
```

### 响应参数说明

| 参数名称       | 参数类型   | 描述                         |
|------------|--------|----------------------------|
| result     | bool   | 请求成功与否。true:请求成功；false请求失败 |
| code       | int    | 错误编码。 0表示success，>0表示失败错误  |
| message    | string | 请求失败返回的错误信息                |
| permission | object | 权限信息                       |
| data       | object | 请求返回的数据                    |
