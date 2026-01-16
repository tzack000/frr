# Change: Add SONiC Integration Test Documentation for Micro-BFD LAG

## Why

Micro-BFD LAG 功能需要与 SONiC 平台组件（teamd、swss、orchagent）进行集成测试，以验证 protodown 机制的正确工作。目前缺乏完整的集成测试说明文档，开发和测试人员难以了解如何搭建测试环境、执行测试用例以及验证预期结果。

## What Changes

- 添加 SONiC 集成测试环境搭建指南
- 添加测试拓扑说明
- 添加测试用例列表及详细步骤
- 添加故障注入和验证方法
- 添加常见问题排查指南

## Impact

- Affected specs: `bfd-lag`
- Affected code: 无代码变更，仅文档
- 风险: 低（纯文档变更）
