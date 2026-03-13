以下是AI给出的Keycloak创建groups claim的指引，仅供参考

在 [Keycloak](https://www.keycloak.org/) 中，将用户所属的“组（Groups）”信息包含在 JWT（JSON Web Token）的 Claims 中，并不是默认行为，需要通过配置 Protocol Mapper 来实现。 [1]
以下是实现“组声明（Groups Claim）”的核心步骤和配置选项：
1. 配置组映射器 (Group Membership Mapper)
   要让 groups 出现在 Token 中，必须在客户端（Client）或客户端范围（Client Scope）中添加映射器： [2]

* 路径：Clients -> 选择你的客户端 -> Client Scopes -> 点击该客户端的 Dedicated scope -> Mappers -> Add mapper -> By configuration。
* 映射器类型：选择 Group Membership。
* 关键设置：
* Name: 映射器名称（如 group-mapper）。
    * Token Claim Name: 在 JWT 中显示的键名，通常设为 groups。
    * Full group path: 如果开启，会显示完整路径（如 /Parent/Child）；如果关闭，仅显示组名（如 Child）。
    * Add to ID token / Access token: 勾选以决定该声明出现在哪个 Token 中。 [3, 4, 5, 6]

2. 将用户加入组
   映射器配置完成后，必须确保用户已分配到相应的组，否则 Token 中不会出现该 Claim： [4, 7, 8]

* 路径：Groups -> 创建或选择组 -> Members -> Add users。
* 或者在 Users 界面中，选择特定用户 -> Groups 选项卡 -> 加入组。 [4]

3. 多值处理 (Multivalued)
   如果一个用户属于多个组，Keycloak 默认会将这些组作为字符串数组（Array of Strings）返回。在映射器设置中，请确保该属性处于启用状态，以保证客户端能正确解析组列表。 [2, 9]
4. 身份提供者映射 (Identity Provider Mapping)
   如果你是通过外部 IDP（如 Okta 或 Azure AD）登录 Keycloak，并希望将外部组映射到 Keycloak 组，需使用 Advanced Claim to Group 映射器： [3, 8, 9]

* 路径：Identity Providers -> 选择提供者 -> Mappers -> Add Mapper。
* 该配置允许根据外部 Token 中的 Claim 自动将用户分配到 Keycloak 的本地组中。 [9, 10]

常见用途与建议

* 角色 vs 组：虽然组可以包含角色，但建议通过组来管理用户组织结构，而通过 [Roles](https://wjw465150.gitbooks.io/keycloak-documentation/content/server_admin/topics/groups/groups-vs-roles.html) 来管理具体应用权限。
* 性能考量：如果用户所属组极其多，会导致 JWT 体积过大，可能触发某些 Web 服务器的 Header 大小限制。 [11, 12, 13, 14]

[1] [https://atchison.dev](https://atchison.dev/returning-keycloak-group-info/#:~:text=It%20is%20mind%20boggling%20that%20group%20membership,default%20by%20Keycloak%20for%20a%20user%20claim/token.)
[2] [https://github.com](https://github.com/keycloak/keycloak/discussions/16469)
[3] [https://infisical.com](https://infisical.com/docs/documentation/platform/sso/keycloak-oidc/group-membership-mapping)
[4] [https://shaaf.dev](https://shaaf.dev/keycloak-tutorial/6-usergroups/)
[5] [https://dev.to](https://dev.to/devaaai/implementing-organization-based-access-control-with-keycloak-42km)
[6] [https://www.youtube.com](https://www.youtube.com/watch?v=0zXr9ELHtiU&t=112)
[7] [https://www.redhat.com](https://www.redhat.com/en/blog/oauth-20-authentication-keycloak#:~:text=Keycloak%20is%20an%20open%20source%20identity%20and,protocols%2C%20including%20OAuth%202.0%2C%20OpenID%2C%20and%20SAML.)
[8] [https://github.com](https://github.com/keycloak/keycloak/issues/12950)
[9] [https://github.com](https://github.com/keycloak/keycloak/discussions/13646)
[10] [https://stackoverflow.com](https://stackoverflow.com/questions/73171868/keycloak-advanced-claim-to-group-identity-provider-mapper-example)
[11] [https://github.com](https://github.com/keycloak/keycloak/discussions/36325)
[12] [https://wjw465150.gitbooks.io](https://wjw465150.gitbooks.io/keycloak-documentation/content/server_admin/topics/groups/groups-vs-roles.html)
[13] [https://github.com](https://github.com/keycloak/keycloak/discussions/29108)
[14] [https://medium.com](https://medium.com/@torinks/keycloak-roles-2a521e64344d#:~:text=Keep%20direct%20role%20assignments%20within%20a%20reasonable,their%20configuration%20and%20will%20reject%20oversized%20headers.)
