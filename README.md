# BlockRDPBrute
## RuntimeEventlogAudit (ring3 plan)
### 通过读取windows实时日志检测RDP连接情况，其中
* EventID = 4624, 登陆成功
* EventID = 4625, 登陆失败
需要特殊关注
### 效果
![](https://github.com/y11en/BlockRDPBrute/blob/master/RuntimeEventLogAudit/img/test.png)

## WFP (ring0 plan)
### 使用 网络协议过滤框架，通过在`FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4`收集对端信息，在`FWPM_LAYER_STREAM_V4`层进行数据包校验（在stream层单独做可能也行，没有验证），判断是不是RDP数据握手包（请求验证），基于2条规则,
* 握手总次数(>=20次)
* 握手频率 (>=2次/1s)
就给你安排了(block)
### 效果
![](https://github.com/y11en/BlockRDPBrute/blob/master/WFP/img/test.png)

## 方案对比
*RuntimeEventlogAudit

* 优点：实现简单、反馈信息多（密码错误，账户不存在等）
* 缺点：在批量暴力破解速率高时(单次耗时<=1s时)，EventLog的读取存在延迟，这样就导致拦截不及时

*WFP

* 优点：真实时拦截
* 缺点：相对实现较复杂些，没有`RuntimeEventlogAudit`获取到的信息多，一定程度上有损网络性能



### 参考
https://github.com/JaredWright/WFPStarterKit [wfp]
https://github.com/raymon-tian/WFPFirewall [wfp]

## bugs&其他
关于bug和其他讨论，欢迎提交issue
