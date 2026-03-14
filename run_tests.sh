#!/bin/bash
# C45144lAI Defense System - Test Suite Runner
# 完整的測試執行和報告生成

set -e

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  🧪 C45144lAI 防禦系統 - 完整測試套件                        ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# 1. 檢查依賴
echo "📦 檢查測試依賴..."
python -m pip list | grep -q pytest || pip install pytest pytest-cov -q
echo "✅ 依賴檢查完成"
echo ""

# 2. 運行所有測試
echo "🧪 運行所有測試 (55 個)..."
python -m pytest tests/ -v --tb=short
echo ""

# 3. 生成覆蓋率報告
echo "📊 生成代碼覆蓋率報告..."
python -m pytest tests/ --cov=src --cov-report=html --cov-report=term-missing -q
echo ""

# 4. 顯示覆蓋率統計
echo "═══════════════════════════════════════════════════════════════"
echo "📈 代碼覆蓋率統計"
echo "═══════════════════════════════════════════════════════════════"
python -m pytest tests/ --cov=src --cov-report=term-missing -q
echo ""

# 5. 顯示完成信息
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  ✅ 測試完成                                                  ║"
echo "╠═══════════════════════════════════════════════════════════════╣"
echo "║  📊 HTML 覆蓋率報告: htmlcov/index.html                       ║"
echo "║  📝 詳細測試報告: TEST_REPORT.md                              ║"
echo "║  🎯 覆蓋率目標: 90%                                           ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
