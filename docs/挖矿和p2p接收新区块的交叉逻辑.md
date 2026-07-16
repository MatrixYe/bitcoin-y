
# 验证的逻辑是通用的e

挖矿得到的新区块和 P2P 收到的新区块，最终都应该走同一条验证和入链流程：

```text
挖矿成功:
CheckWork()
ProcessBlock()
AcceptBlock()
AddToBlockIndex()
SetBestChain()

网络收到区块:
ProcessBlock()
AcceptBlock()
AddToBlockIndex()
SetBestChain()

```