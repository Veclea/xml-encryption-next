/**
 * Vitest 配置文件
 * 优化并发测试性能
 */

import { defineConfig } from 'vitest/config';
import tsconfigPaths from 'vite-tsconfig-paths';

export default defineConfig({
    plugins: [tsconfigPaths()],
    test: {
        // 全局测试超时时间 (毫秒)
        testTimeout: 30000,

        // 全局钩子超时时间 (毫秒)
        hookTimeout: 10000,

        // 并发测试数量
        // 设置为 CPU 核心数或更高以加速测试
        maxConcurrency: 4,

        // 是否并行运行测试文件
        // true = 并行运行所有测试文件 (更快)
        // false = 串行运行测试文件 (更稳定)
        pool: 'threads',

        // 线程池大小
        // 默认为 CPU 核心数
        minThreads: 2,
        maxThreads: 8,

        // 测试文件匹配模式
        include: [
            'test/**/*.test.ts',
            'test/**/*.test.js'
        ],

        // 排除的文件
        exclude: [
            'node_modules/**',
            'dist/**',
            '**/*.d.ts'
        ],

        // 覆盖率配置
        coverage: {
            // 覆盖率提供者
            provider: 'v8', // 或 'istanbul'

            // 报告格式
            reporter: ['text', 'json', 'html'],

            // 覆盖率阈值
            thresholds: {
                global: {
                    statements: 80,
                    branches: 75,
                    functions: 80,
                    lines: 80
                }
            },

            // 包含的文件
            include: ['lib/**/*.js'],

            // 排除的文件
            exclude: [
                'lib/templates/*.js',
                'test/**',
                'node_modules/**'
            ]
        },

        // 日志配置
        logHeapUsage: true,

        // 失败时继续运行其他测试
        bail: 0, // 0 = 不中断，1 = 第一个失败就中断

        // 重试次数
        retry: 1,

        // 是否隔离测试环境
        isolate: true,

        // 环境设置
        environment: 'node',

        // 全局测试设置
        globals: true,

        // 设置文件
        setupFiles: ['./test/setup.js'],

        // 测试前运行
        onConsoleLog(log, type) {
            // 过滤性能测试日志
            if (log.includes('PERFORMANCE BENCHMARK')) {
                return false;
            }
            return true;
        }
    },

    // 构建配置
    build: {
        // 生成 source maps
        sourcemap: true,

        // 代码分割
        rollupOptions: {
            output: {
                // 保留动态导入
                preserveDynamicImports: true
            }
        }
    }
});
