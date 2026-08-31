# kube-security

[English](README.md) | 简体中文

单节点 kind 集群演示**纵深防御的 Kubernetes 安全**,并以 **Jenkins CI 作为 Kubernetes 策略门禁(policy gate)**:这是 Kyverno 集群策略被测试并安装进集群的唯一路径。

**范围:本仓库是策略门禁,不是部署流水线。** 它由**集群运维(cluster operator)**负责。开发者在 `resources/helm/` 下贡献应用部署;本仓库的 CI 决定每一份 manifest 能否运行在租户命名空间中,然后安装做出该决定的策略。部署工作负载是运维的职责,因此**本仓库不包含 CD 流水线**——见*未包含的内容*。

核心理念:**策略即代码,门禁是唯一可信路径。** 策略保存在本仓库并配有离线单元测试;未通过测试的策略永远不会被安装,违反已安装策略集的开发者 manifest 也永远过不了 CI。最终在集群中运行的任何东西,无论由谁、由什么部署,都要由这些策略准入或拒绝。

- 🛠 搭建:[`SETUP_DEMO.md`](SETUP_DEMO.md)

## 快速演示

```bash
# 1. 运行门禁(离线阶段无需集群;安装阶段需要)
kyverno test tests/policies                      # 每条策略的“通过”和“拒绝”行为
kyverno apply policies/ -r <渲染后的 manifests>   # 合规校验 — 见 §如何添加应用部署

# 2. 同一件事的 Jenkins 版本(SETUP_DEMO.md §9):CI job,预期为绿色:
#    工具准备 → 策略单元测试 → 策略合规校验 → IaC 扫描
#    → 策略 schema lint → 策略安装

# 3. 恶意 Pod 在准入阶段被拒绝(门禁已将这些策略以 Enforce 模式安装)
kubectl apply -f resources/admission/pod.attacker.yaml -n tenant-a
# Error: ... image "bitnami/kubectl:latest" is not in the governed image trust list ...

# 4. 租户隔离:以 alice(OIDC)登录,尝试读取 tenant-b
kubectl oidc-login login
kubectl auth can-i get pods -n tenant-b   # no
```

CI校验通过:

<img width="1370" height="79" alt="image" src="https://github.com/user-attachments/assets/2d183d11-8234-4969-83a8-2a45e2187d25" />

CI校验失败 - 阻塞merging:

<img width="1426" height="636" alt="image" src="https://github.com/user-attachments/assets/f57abaaa-8caa-4b8e-9eaa-089b8ad0c152" />


## 目录结构

```
kube-security/
├── README.md                    # 本文件(英文)
├── README.zh-CN.md              # 本文件(中文)
├── SETUP_DEMO.md                # 前置条件:kind 集群、Jenkins、dex、凭据,
│                                #   + 制作演示用签名镜像(build → trivy → cosign sign)
├── docs/
│   └── DESIGN.md                # 完整设计:架构、控制措施、门禁、权衡取舍
├── kind/
│   └── cluster-config.yaml      # kind 配置:OIDC(外部认证)参数 + kubelet 加固
├── policies/                    # Kyverno ClusterPolicies — 每条安全规则一个文件
├── resources/
│   ├── cluster/                 # 租户命名空间、dex(OIDC)、演示用户 RBAC
│   ├── helm/
│   │   └── webapp/              # 开发者拥有的部署 — 门禁负责渲染并检查它们
│   └── admission/
│       └── pod.attacker.yaml    # 恶意 Pod — 手动演示拒绝的目标
├── demo-apps/                   # 演示应用源码 — 用于制作签名镜像
│   ├── shop/                    # tenant-a:nodejs distroless web 服务 :8080 + PVC(日志)
│   └── analytics/               # tenant-b:nodejs API :9090 + PVC(报表数据)
├── tests/
│   ├── policies/<policy>/       # kyverno test 文件:每条策略 ≥1 个通过 + ≥1 个拒绝 fixture
│   └── verify.sh                # 运维侧集群证据(策略、RBAC、kubelet、netpol)
└── workflows/
    └── Jenkinsfile.ci           # 门禁本体:策略测试 + 合规校验 + IaC 扫描 → 安装策略
```

## 如何添加一个应用部署

你的角色是**开发者**。集群运维拥有本仓库、策略和集群;你通过 PR 贡献你的部署,
**门禁才是合并你的那个东西**。

你的镜像由你的应用仓库流水线构建并签名(build → Trivy 扫描 → cosign 签名 → push → 记下
**digest**)。对演示应用,SETUP_DEMO.md §10 会带你一次性制作这些签名镜像。

1. **在你的应用仓库中编写应用** — 构建镜像,通过你自己的开发侧 CI(见
   <https://github.com/PadishahIII/devsecops-demo>),push 到受管镜像仓库,并
   **cosign 签名**。镜像 digest 就是你交付的契约。
2. **添加租户 values 文件** — 复制 `resources/helm/webapp/values-tenant-a.yaml` 为
   `values-<tenant>.yaml`,并设置:`nameOverride`、`service.port` / `containerPort`、
   PVC 大小、ingress 允许的对端(哪些命名空间可以调用本应用),以及开发者拥有的
   镜像 + 证明(attestation):digest 固定的 `image.fullRef`,加上
   `annotations.imageVerified: cosign` 和 `annotations.imageDigest: <digest>`。
   - 如果是**新租户**:在 `resources/cluster/namespaces.yaml` 中添加命名空间(打上
     `tenancy.io/tenant: "true"` 标签),并在 `resources/cluster/rbac.yaml` 中添加
     该租户的 Role/RoleBinding。仅此而已 — 策略通过 label selector 自动覆盖新命名空间,
     合规校验阶段也会自动拾取新的 `values-<tenant>.yaml`(无需改动流水线)。
3. **向本仓库发起 PR。** Jenkins CI 运行门禁,任何一步失败都会阻断合并:
   - `kyverno test tests/policies` — 每条策略的通过*和*拒绝行为,
   - `kyverno apply policies/ -r <你渲染后的 manifests>` — **你的**部署必须通过全部
     13 条策略,直接由你的 values 文件渲染而来,
   - `trivy config --exit-code 1 resources/` — 对你的文件做 IaC 扫描。

   门禁不需要任何应用相关知识:它自动发现 `values-<tenant>.yaml` 并原样渲染,
   因此你的 values 文件就是被检查内容的唯一事实来源。通过校验的渲染 manifests
   会随构建归档(`reports/conformance-rendered/`)。

4. **运维执行合并。** 门禁的最后一个阶段会把 `policies/` 安装进集群
   (`kubectl apply` + 等待 `Ready`)— 这是策略进入集群的唯一路径。此时你的
   manifest 已确认与已安装策略集兼容,归档的构建产物(包括通过校验的渲染 manifests)
   正是运维部署工具所消费的内容。
5. **只有当你改动了策略时才添加测试**:fixture 按策略存放在 `tests/policies/` 下。
   如果你的应用需要新的跨租户网络放行,更新 netpol fixture 和 `tests/verify.sh`
   的预期。
6. **不要**手动 `kubectl apply` 到租户命名空间。这会绕过证明(attestation)机制,
   并被 `require-image-attestation` 拒绝 — 这是设计使然,不是偶然。

## 策略介绍与安全考量

所有策略都是 `validationFailureAction: Enforce` 的 Kyverno `ClusterPolicy` 资源,
作用域限定在打有 `tenancy.io/tenant: "true"` 标签的命名空间(租户层 —
`kyverno`/`platform` 等平台命名空间单独治理)。每条策略都有离线单元测试
(`kyverno test tests/policies`)在门禁中运行,而且**门禁本身就是策略执行阶段**:
只有 lint 干净且通过测试的策略才会被 `kubectl apply` 到集群(DESIGN.md §10.1)。
拒绝行为由 `kyverno test` 离线断言 — 而不是靠在集群里 apply 违规 Pod 重新推导。

| 策略文件                                | 安全考量                                                                                                                                                                                                                                                                                 |
| --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `require-non-root.yaml`                 | 应用进程不得以 root 运行(`runAsNonRoot: true`)。                                                                                                                                                                                                                                         |
| `disallow-privilege-escalation.yaml`    | 每个容器 `allowPrivilegeEscalation: false`(阻断例如 setuid 二进制、`CAP_SYS_PTRACE` 类提权)。                                                                                                                                                                                            |
| `require-readonly-rootfs.yaml`          | `readOnlyRootFilesystem: true` — 被攻陷的进程无法投放工具、持久化或篡改自身文件系统。可写状态放到显式卷(PVC)。                                                                                                                                                                           |
| `require-default-proc-mount.yaml`       | 拒绝 `procMount: Unmasked` — 默认(masked)的 /proc 会隐藏内核内存和其他进程的 `/proc/<pid>/mem`。                                                                                                                                                                                         |
| `disallow-host-namespaces.yaml`         | 禁止 `hostNetwork`/`hostPID`/`hostIPC`。宿主网络还会悄悄绕过 NetworkPolicy — Pod 会直接通过宿主的网络接口通信。                                                                                                                                                                          |
| `require-drop-all-capabilities.yaml`    | `capabilities.drop: [ALL]` — 不保留未使用的 Linux capabilities;只为工作负载可证明需要的能力开例外。                                                                                                                                                                                      |
| `require-selinux-options.yaml`          | 要求 `seLinuxOptions.level` — 细粒度 MAC 标签。_诚实的说明:_ kind 节点并未运行 SELinux,因此在实验环境中这只是规范层面的强制;在启用 SELinux 的节点上,运行时会真正执行它。                                                                                                                 |
| `require-dedicated-serviceaccount.yaml` | 每个应用使用自己的 ServiceAccount;共享的 `default` SA 被禁止(不共享身份,审计链路清晰)。                                                                                                                                                                                                  |
| `require-automount-sa-token-false.yaml` | 不调用 Kubernetes API 的应用不会挂载 SA 凭据 — 消除一个经典的横向移动载体。                                                                                                                                                                                                              |
| `disallow-privileged-containers.yaml`   | 纵深防御:`privileged: true` 永远不允许(完全设备访问 + 几乎全部 capabilities)。                                                                                                                                                                                                           |
| `require-image-allowlist.yaml`          | **受管镜像信任列表** — 只有来自 `docker.io/padishahiii/*`(平台负责构建与扫描的组织)的镜像可以运行。该列表是策略中一个版本化的 `variables` 块,像代码一样评审。(生产变体:ConfigMap + `apiCall` 热更新 — 见 DESIGN.md §6.2。)                                                               |
| `require-image-digest.yaml`             | 镜像必须以 `@sha256:` digest 引用 — 部署中不允许可变 tag。                                                                                                                                                                                                                               |
| `require-image-attestation.yaml`        | **只有经过验证的镜像才被准入。** 应用流水线在 cosign 签名*之前*先用 Trivy 扫描镜像;部署环节 cosign 验证镜像,并在 Pod 模板上盖章 `security.devsecops.io/image-verified=cosign` + 已证明的 digest;本策略同时要求该注释**以及**已证明 digest 与运行镜像一致(堵住“验证后重新打 tag”的漏洞)。 |

**集群级控制**(非 Kyverno):

- **外部 API 认证** — kube-apiserver 通过外部 OIDC issuer(`platform` ns 中的 dex)
  校验 bearer token;身份 + 用户组进入 RBAC。见 `kind/cluster-config.yaml` 与
  SETUP_DEMO.md。
- **RBAC 用对** — 没有人拥有 cluster-admin;每租户 Role/RoleBinding
  (alice→tenant-a,bob→tenant-b);应用 ServiceAccounts 的 API 权限为*零*。
- **kubelet 访问受限** — 匿名认证关闭,只读端口 0,webhook 授权;由
  `tests/verify.sh` 验证(匿名 curl → 401)并通过 kube-bench 佐证。
- **NetworkPolicy** — 每租户默认拒绝(ingress+egress);只允许显式放行
  (DNS;同命名空间;tenant-a → tenant-b:9090,模拟前端→后端)。

**融入门禁的安全考量**(见 DESIGN.md §10):

- **硬编码门禁,不用门禁框架:** 每个工具的退出码直接决定构建失败 —
  `kyverno test`、`kyverno apply`、`trivy --exit-code 1`。本场景足够简单,引入
  发现结果归一化层(姊妹仓库)反而是额外负担。
- **策略执行阶段:** lint + 单元测试 + 合规校验 + IaC 扫描全部通过后,门禁才把
  `policies/` 应用到集群并等待 `Ready` — 因此策略绝不可能在测试之前被强制执行。
- **门禁检查的就是它渲染的内容。** 合规校验按租户渲染真实 chart(`helm template`),
  而不是信任手写 fixture,所以开发者 manifest 里的一次安全上下文改动会在同一个
  commit 内翻转门禁。
- **镜像治理检查到门禁所能检查的极限。** 门禁无法执行 cosign 验证(那需要镜像仓库
  凭据和检查时的网络访问),所以它在 manifest 中强制 digest 固定与 attestation 注释
  形态,由 Kyverno 在准入时强制注释/digest 匹配。签名本身的验证是运维在部署期的
  职责。
- **拒绝路径离线证明**(`kyverno test`,每条策略一个目录),并在手动演示中
  **现场**展示 — 门禁从不要求某个部署必须存在。

## 包含的内容

- 13 条 Kyverno ClusterPolicies(pod 安全、镜像治理)+ 每条策略的单元测试
- Jenkins **CI — 策略门禁**:`kyverno test`(断言)、对开发者 chart 渲染 manifests 的
  `kyverno apply`(合规校验)、Trivy IaC/config 扫描、服务端 schema lint,以及
  **策略安装阶段**(`kubectl apply -f policies/` + `Ready` 等待)
- 每次构建归档门禁证据:策略测试 + 合规校验 + IaC 报告,以及通过校验的每租户
  渲染 manifests — 正是集群运维部署工具所消费的产物
- 多租户模型:2 个租户命名空间、每租户 RBAC、每应用 ServiceAccounts、
  默认拒绝的 NetworkPolicies + 显式跨租户放行
- 演示应用:nodejs **distroless** web 服务 + PVC(shop、analytics)+ 恶意攻击者 Pod
- 镜像治理**达到策略门禁所能强制的程度**:信任列表、digest 固定,以及准入时的
  attestation 注释 + digest 匹配检查(`require-image-attestation`)
- 组件加固:外部 API 认证(OIDC/dex)、最小权限 RBAC、受限 kubelet
  (kube-bench + 未认证请求佐证)
- `tests/verify.sh`:运维侧证据收集器(策略就绪、RBAC 矩阵、kubelet、
  NetworkPolicy 行为)— 只要集群里有已部署的工作负载,就应当运行它

## 未包含的内容

- **CD / 部署流水线** — 有意省略。本仓库是 **Kubernetes 策略门禁演示,不是运维演示**:
  它决定什么*可以*运行,并安装强制该决定的策略。开发期间曾存在
  `workflows/Jenkinsfile.cd`(cosign 验证 → GPG 签名的 chart →
  `helm upgrade --install` → 滚动更新验证);因超出范围被移除,git 历史记录了它的
  工作方式。集群运维自己的部署工具是绿色门禁的消费者。
  - 随之移除的还有 chart 的 **GPG 来源签名** — `helm package --sign`、Jenkins 的
    `helm-signing-key` 凭据、`resources/helm/webapp/keys/public.asc` 和
    `tools/generate-helm-signing-key.sh`。chart 签名属于交付问题,不是策略问题。
    镜像 **cosign** 验证同样保留在部署期。
- **DAST** — 由姊妹仓库 `devsecops-demo` 覆盖(集群内 ZAP + DAST 感知的门禁)
- **镜像 build/push/scan 流水线** — 你的应用仓库的职责;SETUP_DEMO.md 演示制作
  演示签名镜像(build → trivy → cosign sign → push)。cosign *签名*本身在
  `devsecops-demo` 中演示。
- **门禁框架**(姊妹仓库的发现结果归一化)— 本仓库在流水线中硬编码失败门禁
  (工具退出码)
- **PodSecurityAdmission 标签** — 与这些策略互补(PSS `restricted` ≈ P1–P6);
  选择逐条规则的策略是为了粒度和可读的拒绝消息
- **审计日志、etcd 加固、节点加固** — kind 托管或演示价值较低;kube-bench 用于
  取证,不作为控制措施
- **服务网格 / mTLS、secrets 管理(SOPS/SealedSecrets)、GitOps(ArgoCD)、
  ResourceQuota/LimitRange、灾备** — 现实的扩展方向,在 DESIGN.md §13 中列为
  未来工作
