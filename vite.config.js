import { defineConfig } from 'vite';
import { resolve } from 'path';
console.log(__dirname)
export default defineConfig({
    // 明确指定构建目标为 Node，因为涉及 crypto 和 fs 等
    build: {
        target: 'node18', // 或更高，取决于您的最低支持版本
        minify:false,
        lib: {
            entry: resolve(__dirname, 'lib/index.js'), // 入口文件
            name: 'SamlXmlEnc', // 全局变量名（如果是 UMD/IIFE，CJS/ES 忽略此项）
            formats: ['es'], // 输出 ES Module 和 CommonJS
            fileName: (format, entryName) => `${entryName}.js`,
        },
        rolldownOptions: {
            // 关键：排除 Node 内置模块和第三方依赖
            external: [
                'crypto',
                'node-forge',
                '@xmldom/xmldom',
                'xpath',
                'escape-html',
                /^node:/, // 排除所有 node: 前缀的模块
            ],
            output: {
                // 确保动态导入不会被错误地内联或移除
                preserveDynamicImports: true,

                // 对于 CJS 格式，确保互操作性
                interop: 'auto',

                // 如果需要生成 sourcemap 方便调试
                sourcemap: true,
                // 关键配置：保留模块结构
                preserveModules: true,
                // 将结构保留在 dist/es 目录下
                dir: 'dist',
                // 输出为 es 模块
                format: 'es',
                entryFileNames: '[name].js'
            },
        },
        // 优化依赖预构建（主要用于 dev 模式，build 模式影响较小但保留无妨）
        optimizeDeps: {
            include: ['node-forge'],
        },
    },
    test: {
        // Vitest 配置，如果需要
        environment: 'node',
    },
});