#!/bin/bash
# ============================================================
# ngx-lua-waf 增强版 - 现代安装/更新脚本
# ============================================================
# 功能：
#   - 不编译 Nginx/OpenResty（假设已预装）
#   - 部署/更新 WAF 代码
#   - 自动备份配置
#   - 创建日志目录并设置权限
#   - 测试 nginx 配置并平滑 reload/restart
#
# 用法：
#   ./install.sh install  /path/to/deploy     # 首次部署
#   ./install.sh update   /path/to/deploy     # 更新代码（保留 config.lua）
#   ./install.sh check    /path/to/deploy     # 仅检查部署状态
# ============================================================

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 默认参数
ACTION="${1:-install}"
DEPLOY_DIR="${2:-/u/nginx/ngx_lua_waf}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKUP_DIR="${DEPLOY_DIR}/.backup/$(date +%Y%m%d_%H%M%S)"

# Nginx 可执行文件路径（自动检测）
NGINX_BIN=""

# ============================================================
# 辅助函数
# ============================================================

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

detect_nginx() {
    if command -v openresty &>/dev/null; then
        NGINX_BIN="$(command -v openresty)"
        log_info "检测到 OpenResty: $NGINX_BIN"
        return 0
    fi
    if command -v nginx &>/dev/null; then
        NGINX_BIN="$(command -v nginx)"
        log_info "检测到 Nginx: $NGINX_BIN"
        return 0
    fi
    # 尝试常见路径
    for path in /usr/local/openresty/nginx/sbin/nginx /usr/local/nginx/sbin/nginx /usr/sbin/nginx /opt/openresty/nginx/sbin/nginx; do
        if [ -x "$path" ]; then
            NGINX_BIN="$path"
            log_info "检测到 Nginx: $NGINX_BIN"
            return 0
        fi
    done
    log_error "未找到 nginx 或 openresty 可执行文件"
    return 1
}

check_nginx_lua() {
    log_step "检查 Nginx Lua 模块..."
    local lua_support
    lua_support=$($NGINX_BIN -V 2>&1 | grep -o 'lua-nginx-module\|ngx_http_lua_module' || true)
    if [ -z "$lua_support" ]; then
        log_error "当前 Nginx 未编译 lua-nginx-module，无法使用 WAF"
        log_error "请安装 OpenResty 或重新编译 Nginx 时加入 --add-module=lua-nginx-module"
        exit 1
    fi
    log_info "Nginx Lua 模块已就绪"
}

get_nginx_user() {
    local user
    user=$($NGINX_BIN -V 2>&1 | grep "configure arguments" | grep -oP '(?<=--user=)[^ ]+' || true)
    if [ -z "$user" ]; then
        user=$(grep -E '^user\s+' "$(dirname "$(dirname "$NGINX_BIN")")/conf/nginx.conf" 2>/dev/null | awk '{print $2}' | tr -d ';' || true)
    fi
    if [ -z "$user" ]; then
        user="daemon"
        log_warn "未检测到 nginx worker 用户，默认使用: $user"
    else
        log_info "Nginx worker 用户: $user"
    fi
    echo "$user"
}

create_log_dir() {
    log_step "创建日志目录..."
    local logdir
    # 尝试从 config.lua 读取 logdir
    if [ -f "${DEPLOY_DIR}/config.lua" ]; then
        logdir=$(grep -E '^logdir\s*=' "${DEPLOY_DIR}/config.lua" | sed 's/.*=\s*"\(.*\)".*/\1/' | tr -d '\r')
    fi
    # 如果 config.lua 中没定义或部署目录为空，使用默认值
    if [ -z "$logdir" ]; then
        logdir="/u/medsci/logs/nginx"
        log_warn "config.lua 中未找到 logdir，使用默认路径: $logdir"
    fi

    if [ ! -d "$logdir" ]; then
        mkdir -p "$logdir"
        log_info "创建日志目录: $logdir"
    else
        log_info "日志目录已存在: $logdir"
    fi

    # 设置权限
    local nginx_user
    nginx_user=$(get_nginx_user)
    chown -R "${nginx_user}:${nginx_user}" "$logdir" 2>/dev/null || true
    chmod 755 "$logdir"
    log_info "设置日志目录权限: $(ls -ld "$logdir")"

    # 返回 logdir 供后续使用
    echo "$logdir"
}

backup_config() {
    log_step "备份现有配置..."
    mkdir -p "$BACKUP_DIR"
    if [ -f "${DEPLOY_DIR}/config.lua" ]; then
        cp "${DEPLOY_DIR}/config.lua" "${BACKUP_DIR}/config.lua"
        log_info "已备份 config.lua -> ${BACKUP_DIR}/"
    fi
    if [ -f "${DEPLOY_DIR}/nginx-example.conf" ]; then
        cp "${DEPLOY_DIR}/nginx-example.conf" "${BACKUP_DIR}/nginx-example.conf"
    fi
}

deploy_files() {
    log_step "部署 WAF 文件到 ${DEPLOY_DIR}..."
    mkdir -p "$DEPLOY_DIR"

    # 核心文件
    cp -f "${SCRIPT_DIR}/config.lua" "$DEPLOY_DIR/"
    cp -f "${SCRIPT_DIR}/init.lua" "$DEPLOY_DIR/"
    cp -f "${SCRIPT_DIR}/waf.lua" "$DEPLOY_DIR/"
    cp -f "${SCRIPT_DIR}/response.lua" "$DEPLOY_DIR/"
    cp -f "${SCRIPT_DIR}/nginx-example.conf" "$DEPLOY_DIR/"

    # lib 目录
    mkdir -p "${DEPLOY_DIR}/lib"
    cp -f "${SCRIPT_DIR}/lib/"*.lua "${DEPLOY_DIR}/lib/"

    # wafconf 目录
    if [ -d "${DEPLOY_DIR}/wafconf" ] && [ "$(ls -A "${DEPLOY_DIR}/wafconf" 2>/dev/null)" ]; then
        log_warn "wafconf 目录已存在且非空，保留现有规则文件"
        # 只复制不存在的文件
        for f in "${SCRIPT_DIR}/wafconf/"*; do
            local basename
            basename=$(basename "$f")
            if [ ! -f "${DEPLOY_DIR}/wafconf/${basename}" ]; then
                cp "$f" "${DEPLOY_DIR}/wafconf/"
                log_info "新增规则文件: wafconf/${basename}"
            fi
        done
    else
        mkdir -p "${DEPLOY_DIR}/wafconf"
        cp -f "${SCRIPT_DIR}/wafconf/"* "${DEPLOY_DIR}/wafconf/"
        log_info "复制规则文件到 wafconf/"
    fi

    # waf-cli 工具
    if [ -f "${SCRIPT_DIR}/waf-cli" ]; then
        cp -f "${SCRIPT_DIR}/waf-cli" "${DEPLOY_DIR}/"
        chmod +x "${DEPLOY_DIR}/waf-cli"
        log_info "已部署 waf-cli"
    fi

    log_info "文件部署完成"
}

update_files() {
    log_step "更新 WAF 文件到 ${DEPLOY_DIR}..."
    mkdir -p "$DEPLOY_DIR"

    # 更新核心代码（不覆盖 config.lua）
    cp -f "${SCRIPT_DIR}/init.lua" "$DEPLOY_DIR/"
    cp -f "${SCRIPT_DIR}/waf.lua" "$DEPLOY_DIR/"
    cp -f "${SCRIPT_DIR}/response.lua" "$DEPLOY_DIR/"
    cp -f "${SCRIPT_DIR}/nginx-example.conf" "$DEPLOY_DIR/"

    # lib 目录
    mkdir -p "${DEPLOY_DIR}/lib"
    cp -f "${SCRIPT_DIR}/lib/"*.lua "${DEPLOY_DIR}/lib/"

    # wafconf 目录 - update 模式下也保留现有规则，只新增
    if [ -d "${SCRIPT_DIR}/wafconf" ]; then
        mkdir -p "${DEPLOY_DIR}/wafconf"
        for f in "${SCRIPT_DIR}/wafconf/"*; do
            local basename
            basename=$(basename "$f")
            if [ ! -f "${DEPLOY_DIR}/wafconf/${basename}" ]; then
                cp "$f" "${DEPLOY_DIR}/wafconf/"
                log_info "新增规则文件: wafconf/${basename}"
            fi
        done
    fi

    # waf-cli 工具
    if [ -f "${SCRIPT_DIR}/waf-cli" ]; then
        cp -f "${SCRIPT_DIR}/waf-cli" "${DEPLOY_DIR}/"
        chmod +x "${DEPLOY_DIR}/waf-cli"
    fi

    log_info "文件更新完成（config.lua 已保留）"
}

check_deploy() {
    log_step "检查部署状态..."
    local errors=0

    # 检查核心文件
    for f in config.lua init.lua waf.lua response.lua; do
        if [ ! -f "${DEPLOY_DIR}/${f}" ]; then
            log_error "缺失核心文件: ${DEPLOY_DIR}/${f}"
            ((errors++))
        fi
    done

    # 检查 lib
    for f in cache.lua utils.lua cc_enhanced.lua; do
        if [ ! -f "${DEPLOY_DIR}/lib/${f}" ]; then
            log_error "缺失库文件: lib/${f}"
            ((errors++))
        fi
    done

    # 检查 wafconf
    if [ ! -d "${DEPLOY_DIR}/wafconf" ]; then
        log_error "缺失规则目录: ${DEPLOY_DIR}/wafconf"
        ((errors++))
    fi

    # 检查 logdir
    local logdir
    logdir=$(grep -E '^logdir\s*=' "${DEPLOY_DIR}/config.lua" 2>/dev/null | sed 's/.*=\s*"\(.*\)".*/\1/' | tr -d '\r' || true)
    if [ -n "$logdir" ] && [ ! -d "$logdir" ]; then
        log_warn "日志目录不存在: $logdir"
    fi

    # 检查 nginx 配置中是否引用了 WAF
    local nginx_conf
    nginx_conf=$(dirname "$(dirname "$NGINX_BIN")")/conf/nginx.conf
    if [ -f "$nginx_conf" ]; then
        if grep -q "waf.lua" "$nginx_conf" 2>/dev/null; then
            log_info "nginx.conf 已引用 waf.lua"
        else
            log_warn "nginx.conf 中未找到 waf.lua 引用，请手动配置"
        fi
    fi

    if [ "$errors" -eq 0 ]; then
        log_info "部署状态检查通过"
    else
        log_error "发现 ${errors} 个问题，请检查"
        exit 1
    fi
}

show_summary() {
    echo ""
    echo "========================================"
    echo -e "${GREEN}部署摘要${NC}"
    echo "========================================"
    echo "部署目录: ${DEPLOY_DIR}"
    echo "备份目录: ${BACKUP_DIR}"
    echo "Nginx 路径: ${NGINX_BIN}"
    echo ""
    echo "下一步操作:"
    echo "  1. 编辑 nginx.conf，参考 ${DEPLOY_DIR}/nginx-example.conf"
    echo "  2. 按需修改 ${DEPLOY_DIR}/config.lua"
    echo "  3. 执行: ${NGINX_BIN} -t"
    if [ "$ACTION" == "install" ]; then
        echo "  4. 首次部署建议执行: ${NGINX_BIN} -s stop && ${NGINX_BIN}"
    else
        echo "  4. 执行: ${NGINX_BIN} -s reload"
    fi
    echo "========================================"
}

# ============================================================
# 主流程
# ============================================================

case "$ACTION" in
    install)
        log_info "开始安装 ngx-lua-waf 到 ${DEPLOY_DIR}"
        detect_nginx
        check_nginx_lua
        backup_config
        deploy_files
        create_log_dir >/dev/null
        check_deploy
        show_summary
        ;;
    update)
        log_info "开始更新 ngx-lua-waf 到 ${DEPLOY_DIR}"
        detect_nginx
        check_nginx_lua
        backup_config
        update_files
        create_log_dir >/dev/null
        check_deploy
        show_summary
        ;;
    check)
        log_info "检查部署状态: ${DEPLOY_DIR}"
        detect_nginx
        check_nginx_lua
        check_deploy
        ;;
    *)
        echo "用法: $0 {install|update|check} [部署目录]"
        echo ""
        echo "  install  首次部署（覆盖 config.lua）"
        echo "  update   更新代码（保留 config.lua）"
        echo "  check    仅检查部署状态"
        echo ""
        echo "示例:"
        echo "  $0 install /u/nginx/ngx_lua_waf"
        echo "  $0 update  /u/nginx/ngx_lua_waf"
        exit 1
        ;;
esac
