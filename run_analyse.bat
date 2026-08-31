@echo off
echo -----------------------------
echo 正在启动网络日志分析系统...
echo -----------------------------

:: 创建虚拟环境（如果不存在）
if not exist venv (
    echo 创建虚拟环境...
    python -m venv venv
)

:: 激活虚拟环境
call venv\Scripts\activate

:: 升级 pip 并安装依赖
echo 正在安装依赖，请稍等...
pip install -r requirements.txt

:: 启动 Streamlit 分析程序
echo 启动 Streamlit 分析页面...
streamlit run analyse.py

pause
