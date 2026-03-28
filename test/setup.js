/**
 * 测试设置文件
 * 配置全局测试环境
 */

import { beforeAll, afterAll } from 'vitest';

// 全局测试前执行
beforeAll(() => {
    // 增加 Node.js 内存限制 (用于大文件测试)
    if (typeof gc !== 'undefined') {
        // 如果启用了垃圾回收，运行一次 GC
        gc();
    }
}, 10000);

// 全局测试后执行
afterAll(() => {
    // 清理资源
    if (typeof gc !== 'undefined') {
        gc();
    }
}, 10000);
