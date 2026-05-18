# 腾讯云日志服务 CLS DataSight 演示示例

本项目用于演示配合 [CLS DataSight](https://cloud.tencent.com/document/product/614/39331) 使用的相关示例，配合反向代理实现自定义需求。

使用者可根据实际情况调整示例内容，再用于生产环境中。

目录：

[自定义域名](./custom-domain/README.md)

[登录校验代理](./auth-proxy/README.md)

## DataSight 域名说明

CLS DataSight 当前同时支持以下两套域名：

| 类型 | 示例 | 适用范围 |
| --- | --- | --- |
| 新域名 | `xxxxx(.internal)?.clsconsole.tencentcls.com` | **后续新增实例只支持新域名**；老实例若已分配也可访问 |
| 老域名 | `xxxxx(.internal)?.clsconsole.tencent-cloud.com` | 仅老实例可用，不会下线；新增实例不会再分配老域名 |

> 其中 `xxxxx` 是 DataSight 实例 ID，`.internal` 子域名表示腾讯云 VPC 内网访问域名。

### 请先确认您实例使用的域名

由于不同实例的可用域名不同，**接入示例前请先确认您 DataSight 实例的实际域名**，请勿直接照搬示例中的域名。两种确认方式：

1. **控制台**：登录腾讯云 [CLS DataSight 控制台](https://console.cloud.tencent.com/cls)，进入对应 DataSight 实例的详情/域名信息页面查看；
2. **云API**：调用 CLS [DescribeKafkaConsumer/DescribeAlarms 等] 的 DataSight 实例查询接口，从返回的实例信息中读取 `Domain` / `InternalDomain` 字段（具体接口请参考 [CLS API 文档](https://cloud.tencent.com/document/product/614/39331)）。

### 如何在示例配置中使用您的域名

本仓库中所有 Nginx 示例配置（`custom-domain/*.conf`、`auth-proxy/**/*.conf`）默认占位为新域名 `clsconsole.tencentcls.com`：

1. 将 `proxy_pass` 后的域名替换为您实例的**实际域名**（可能是 `clsconsole.tencentcls.com` 或 `clsconsole.tencent-cloud.com`，以控制台/API 查询结果为准）；
2. 示例中的 `proxy_redirect` 正则已通过 `(?:tencent-cloud|tencentcls)` 同时兼容新旧两套域名，**无需为域名而修改正则**；
3. `reload nginx` 即可生效，无需重启反向代理服务，自定义域名/登录代理逻辑不受影响。

如您正在维护自定义脚本或代码，且其中硬编码了 `clsconsole.tencent-cloud.com`，建议参考示例中的非捕获分组写法 `(?:tencent-cloud|tencentcls)` 兼容新旧域名，以免后续新增实例无法解析。
