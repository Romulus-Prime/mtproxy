#!/bin/bash
WORKDIR=$(dirname $(readlink -f $0))
cd $WORKDIR
pid_file=$WORKDIR/pid/pid_mtproxy

check_sys() {
    local checkType=$1
    local value=$2

    local release=''
    local systemPackage=''

    if [[ -f /etc/redhat-release ]]; then
        release="centos"
        systemPackage="yum"
    elif grep -Eqi "debian|raspbian" /etc/issue; then
        release="debian"
        systemPackage="apt"
    elif grep -Eqi "ubuntu" /etc/issue; then
        release="ubuntu"
        systemPackage="apt"
    elif grep -Eqi "centos|red hat|redhat" /etc/issue; then
        release="centos"
        systemPackage="yum"
    elif grep -Eqi "debian|raspbian" /proc/version; then
        release="debian"
        systemPackage="apt"
    elif grep -Eqi "ubuntu" /proc/version; then
        release="ubuntu"
        systemPackage="apt"
    elif grep -Eqi "centos|red hat|redhat" /proc/version; then
        release="centos"
        systemPackage="yum"
    fi

    if [[ "${checkType}" == "sysRelease" ]]; then
        if [ "${value}" == "${release}" ]; then
            return 0
        else
            return 1
        fi
    elif [[ "${checkType}" == "packageManager" ]]; then
        if [ "${value}" == "${systemPackage}" ]; then
            return 0
        else
            return 1
        fi
    fi
}

function abs() {
    echo ${1#-};
}

function get_ip_public() {
    public_ip=$(curl -s https://api.ip.sb/ip -A Mozilla --ipv4)
    [ -z "$public_ip" ] && public_ip=$(curl -s ipinfo.io/ip -A Mozilla --ipv4)
    echo $public_ip
}

function get_ip_private() {
    echo $(ip a | grep inet | grep -v 127.0.0.1 | grep -v inet6 | awk '{print $2}' | cut -d "/" -f1 | awk 'NR==1 {print $1}')
}

function get_local_ip(){
  ip a | grep inet | grep 127.0.0.1 > /dev/null 2>&1
  if [[ $? -eq 1 ]];then
    echo $(get_ip_private)
  else
    echo "127.0.0.1"
  fi
}

function get_nat_ip_param() {
    nat_ip=$(get_ip_private)
    public_ip=$(get_ip_public)
    nat_info=""
    if [[ $nat_ip != $public_ip ]]; then
        nat_info="--nat-info ${nat_ip}:${public_ip}"
    fi
    echo $nat_info
}

function get_cpu_core() {
    echo $(cat /proc/cpuinfo | grep "processor" | wc -l)
}

function get_architecture() {
    local architecture=""
    case $(uname -m) in
    i386) architecture="386" ;;
    i686) architecture="386" ;;
    x86_64) architecture="amd64" ;;
    arm | aarch64 | aarch) dpkg --print-architecture | grep -q "arm64" && architecture="arm64" || architecture="armv6l" ;;
    *) echo "Unsupported system architecture "$(uname -m) && exit 1 ;;
    esac
    echo $architecture
}

function build_mtproto() {
    cd $WORKDIR

    local platform=$(uname -m)
    if [[ -z "$1" ]]; then
        echo "Missing parameter"
        exit 1
    fi

    do_install_build_dep

    rm -rf build
    mkdir build && cd build

    if [[ "1" == "$1" ]]; then
         if [ -d 'MTProxy' ]; then
            rm -rf 'MTProxy'
        fi

        git clone https://github.com/ellermister/MTProxyC --depth=1 MTProxy
        cd MTProxy && make && cd objs/bin &&  chmod +x mtproto-proxy

        if [ ! -f "./mtproto-proxy" ]; then
            echo "mtproto-proxy Compilation failed"
            exit 1
        fi

        cp -f mtproto-proxy $WORKDIR
        

        # clean
        rm -rf 'MTProxy'

    elif [[ "2" == "$1" ]]; then
        # golang
        local arch=$(get_architecture)

        #  https://go.dev/dl/go1.18.4.linux-amd64.tar.gz
        local golang_url="https://go.dev/dl/go1.18.4.linux-$arch.tar.gz"
        wget $golang_url -O golang.tar.gz
        rm -rf go && tar -C . -xzf golang.tar.gz
        export PATH=$PATH:$(pwd)/go/bin

        go version
        if [[ $? != 0 ]]; then
            local uname_m=$(uname -m)
            local architecture_origin=$(dpkg --print-architecture)
            echo -e "[\033[33mError\033[0m] golang download failed, please check!!! arch: $arch, platform: $platform,  uname: $uname_m, architecture_origin: $architecture_origin download url: $golang_url"
            exit 1
        fi

        rm -rf build-mtg
        git clone https://github.com/9seconds/mtg.git -b v1 build-mtg
        cd build-mtg && git reset --hard 9d67414db633dded5f11d549eb80617dc6abb2c3  && make static

        if [[ ! -f "./mtg" ]]; then
            echo -e "[\033[33mError\033[0m] Build fail for mtg, please check!!! $arch"
            exit 1
        fi

        cp -f mtg $WORKDIR && chmod +x $WORKDIR/mtg
    fi

    # clean
    cd $WORKDIR
    rm -rf build

}

function get_mtg_provider() {
    source ./mtp_config

    local arch=$(get_architecture)
    if [[ "$arch" != "amd64" && $provider -eq 1 ]]; then
        provider=2
    fi

    if [ $provider -eq 1 ]; then
        echo "mtproto-proxy"
    elif [ $provider -eq 2 ]; then
        echo "mtg"
    else
        echo "Configuration error, please reinstall"
        exit 1
    fi
}

function is_installed() {
    if [ ! -f "$WORKDIR/mtp_config" ]; then
        return 1
    fi
    return 0
}


function kill_process_by_port() {
    pids=$(get_pids_by_port $1)
    if [ -n "$pids" ]; then
        kill -9 $pids
    fi
}

function get_pids_by_port() {
    echo $(netstat -tulpn 2>/dev/null | grep ":$1 " | awk '{print $7}' | sed 's|/.*||')
}

function is_port_open() {
    pids=$(get_pids_by_port $1)

    if [ -n "$pids" ]; then
        return 0
    else
        return 1
    fi
}


function is_running_mtp() {
    if [ -f $pid_file ]; then

        if is_pid_exists $(cat $pid_file); then
            return 0
        fi
    fi
    return 1
}

function is_supported_official_version() {
    local arch=$(uname -m)
    if [[ "$arch" == "x86_64" ]]; then
        return 0
    else
        return 1
    fi
}

function is_pid_exists() {
    # check_ps_not_install_to_install
    local exists=$(ps aux | awk '{print $2}' | grep -w $1)
    if [[ ! $exists ]]; then
        return 1
    else
        return 0
    fi
}

do_install() {
    cd $WORKDIR

    mtg_provider=$(get_mtg_provider)

    if [[ "$mtg_provider" == "mtg" ]]; then
        local arch=$(get_architecture)
        local mtg_url=https://github.com/9seconds/mtg/releases/download/v2.1.7/mtg-2.1.7-linux-amd64.tar.gz
        wget $mtg_url -O mtg.tar.gz
        tar -xzvf mtg.tar.gz mtg-2.1.7-linux-$arch/mtg --strip-components 1

        [[ -f "./mtg" ]] && ./mtg && echo "Installed for mtg"
    else
        wget https://github.com/ellermister/mtproxy/releases/download/0.03/mtproto-proxy -O mtproto-proxy -q
        chmod +x mtproto-proxy
    fi

    if [ ! -d "./pid" ]; then
        mkdir "./pid"
    fi

}

print_line() {
    echo -e "========================================="
}

do_kill_process() {
    cd $WORKDIR
    source ./mtp_config

    if is_port_open $port; then
        echo "Detected port $port is occupied, preparing to kill the process!"
        kill_process_by_port $port
    fi
    
    if is_port_open $web_port; then
        echo "Detected port $web_port is occupied, preparing to kill the process!"
        kill_process_by_port $web_port
    fi
}

do_check_system_datetime_and_update() {
    dateFromLocal=$(date +%s)
    dateFromServer=$(date -d "$(curl -v --silent ip.sb 2>&1 | grep Date | sed -e 's/< Date: //')" +%s)
    offset=$(abs $(( "$dateFromServer" - "$dateFromLocal")))
    tolerance=60
    if [ "$offset" -gt "$tolerance" ];then
        echo "System time is not synchronized with world time, updating now"
        ntpdate -u time.google.com
    fi
}

do_install_basic_dep() {
    if check_sys packageManager yum; then
        yum install -y iproute curl wget procps-ng.x86_64 net-tools ntp
    elif check_sys packageManager apt; then
        apt install -y iproute2 curl wget procps net-tools ntpdate
    fi

    return 0
}

do_install_build_dep() {
    if check_sys packageManager yum; then
        yum install -y git  openssl-devel zlib-devel
        yum groupinstall -y "Development Tools"
    elif check_sys packageManager apt; then
        apt install -y git curl  build-essential libssl-dev zlib1g-dev
    fi
    return 0
}

do_config_mtp() {
    cd $WORKDIR

    while true; do
        default_provider=1
        echo -e "Please select which program version to install"
        echo -e "1. Telegram official version (C language, some issues, only supports x86_64)"
        echo -e "2. 9seconds third-party version (better compatibility)"

        if ! is_supported_official_version; then
            echo -e "\n[\033[33mNotice\033[0m] Your system does not support the official version\n"
        fi

        read -p "(Default version: ${default_provider}):" input_provider
        [ -z "${input_provider}" ] && input_provider=${default_provider}
        expr ${input_provider} + 1 &>/dev/null
        if [ $? -eq 0 ]; then
            if [ ${input_provider} -ge 1 ] && [ ${input_provider} -le 2 ] && [ ${input_provider:0:1} != 0 ]; then
                echo
                echo "---------------------------"
                echo "provider = ${input_provider}"
                echo "---------------------------"
                echo
                break
            fi
        fi
        echo -e "[\033[33mError\033[0m] Please re-enter the program version [1-65535]\n"
    done

    while true; do
        default_port=443
        echo -e "Please enter a client connection port [1-65535]"
        read -p "(Default port: ${default_port}):" input_port
        [ -z "${input_port}" ] && input_port=${default_port}
        expr ${input_port} + 1 &>/dev/null
        if [ $? -eq 0 ]; then
            if [ ${input_port} -ge 1 ] && [ ${input_port} -le 65535 ] && [ ${input_port:0:1} != 0 ]; then
                echo
                echo "---------------------------"
                echo "port = ${input_port}"
                echo "---------------------------"
                echo
                break
            fi
        fi
        echo -e "[\033[33mError\033[0m] Please re-enter a client connection port [1-65535]"
    done

    # Management Port
    while true; do
        default_manage=8888
        echo -e "Please enter a management port [1-65535]"
        read -p "(Default port: ${default_manage}):" input_manage_port
        [ -z "${input_manage_port}" ] && input_manage_port=${default_manage}
        expr ${input_manage_port} + 1 &>/dev/null
        if [ $? -eq 0 ] && [ $input_manage_port -ne $input_port ]; then
            if [ ${input_manage_port} -ge 1 ] && [ ${input_manage_port} -le 65535 ] && [ ${input_manage_port:0:1} != 0 ]; then
                echo
                echo "---------------------------"
                echo "manage port = ${input_manage_port}"
                echo "---------------------------"
                echo
                break
            fi
        fi
        echo -e "[\033[33mError\033[0m] Please re-enter a management port [1-65535]"
    done

    # domain
    while true; do
        default_domain="azure.microsoft.com"
        echo -e "Please enter a domain name for TLS camouflage："
        read -p "(Default domain: ${default_domain}):" input_domain
        [ -z "${input_domain}" ] && input_domain=${default_domain}
        http_code=$(curl -I -m 10 -o /dev/null -s -w %{http_code} $input_domain)
        if [ $http_code -eq "200" ] || [ $http_code -eq "302" ] || [ $http_code -eq "301" ]; then
            echo
            echo "---------------------------"
            echo "Camouflage domain = ${input_domain}"
            echo "---------------------------"
            echo
            break
        fi
        echo -e "[\033[33mStatus code：${http_code}Error\033[0m] Domain is unreachable, please try another one!"
    done

    # config info
    public_ip=$(get_ip_public)
    secret=$(gen_rand_hex 32)

    # proxy tag
    while true; do
        default_tag=""
        echo -e "Please enter your proxy promotion TAG："
        echo -e "If you don’t have one, contact @MTProxybot to create your TAG, you may need the following information："
        echo -e "IP: ${public_ip}"
        echo -e "PORT: ${input_port}"
        echo -e "SECRET(You can fill in anything): ${secret}"
        read -p "(Leave empty to skip):" input_tag
        [ -z "${input_tag}" ] && input_tag=${default_tag}
        if [ -z "$input_tag" ] || [[ "$input_tag" =~ ^[A-Za-z0-9]{32}$ ]]; then
            echo
            echo "---------------------------"
            echo "PROXY TAG = ${input_tag}"
            echo "---------------------------"
            echo
            break
        fi
        echo -e "[\033[33mError\033[0m] Incorrect TAG format!"
    done

    cat >./mtp_config <<EOF
#!/bin/bash
secret="${secret}"
port=${input_port}
web_port=${input_manage_port}
domain="${input_domain}"
proxy_tag="${input_tag}"
provider=${input_provider}
EOF
    echo -e "Configuration generated successfully!"
}

function str_to_hex() {
    string=$1
    hex=$(printf "%s" "$string" | od -An -tx1 | tr -d ' \n')
    echo $hex
}

function gen_rand_hex() {
    local result=$(dd if=/dev/urandom bs=1 count=500 status=none | od -An -tx1 | tr -d ' \n')
    echo "${result:0:$1}"
}

info_mtp() {
    if [[ "$1" == "ingore" ]] || is_running_mtp; then
        source ./mtp_config
        public_ip=$(get_ip_public)

        domain_hex=$(str_to_hex $domain)

        client_secret="ee${secret}${domain_hex}"
        echo -e "TMProxy+TLS代理: \033[32mRunning\033[0m"
        echo -e "Server IP：\033[31m$public_ip\033[0m"
        echo -e "Server Port：\033[31m$port\033[0m"
        echo -e "MTProxy Secret:  \033[31m$client_secret\033[0m"
        echo -e "TGOne-click link: https://t.me/proxy?server=${public_ip}&port=${port}&secret=${client_secret}"
        echo -e "TGOne-click link: tg://proxy?server=${public_ip}&port=${port}&secret=${client_secret}"
    else
        echo -e "TMProxy+TLS代理: \033[33mStopped\033[0m"
    fi
}

function get_run_command(){
  cd $WORKDIR
  mtg_provider=$(get_mtg_provider)
  source ./mtp_config
  if [[ "$mtg_provider" == "mtg" ]]; then
      domain_hex=$(str_to_hex $domain)
      client_secret="ee${secret}${domain_hex}"
      local local_ip=$(get_local_ip)
      public_ip=$(get_ip_public)
      
      # ./mtg simple-run -n 1.1.1.1 -t 30s -a 512kib 0.0.0.0:$port $client_secret >/dev/null 2>&1 &
      [[ -f "./mtg" ]] || (echo -e "Notice：\033[33m MTProxy Proxy program not found, please reinstall! \033[0m" && exit 1)
      echo "./mtg run $client_secret $proxy_tag -b 0.0.0.0:$port --multiplex-per-connection 500 --prefer-ip=ipv6 -t $local_ip:$web_port" -4 "$public_ip:$port"
  else
      curl -s https://core.telegram.org/getProxyConfig -o proxy-multi.conf
      curl -s https://core.telegram.org/getProxySecret -o proxy-secret
      nat_info=$(get_nat_ip_param)
      workerman=$(get_cpu_core)
      tag_arg=""
      [[ -n "$proxy_tag" ]] && tag_arg="-P $proxy_tag"
      echo "./mtproto-proxy -u nobody -p $web_port -H $port -S $secret --aes-pwd proxy-secret proxy-multi.conf -M $workerman $tag_arg --domain $domain $nat_info --ipv6"
  fi
}

run_mtp() {
    cd $WORKDIR

    if is_running_mtp; then
        echo -e "Notice：\033[33mMTProxyAlready running, please do not start again!\033[0m"
    else
        do_kill_process
        do_check_system_datetime_and_update

        local command=$(get_run_command)
        echo $command
        $command >/dev/null 2>&1 &

        echo $! >$pid_file
        sleep 2
        info_mtp
    fi
}


daemon_mtp() {
    cd $WORKDIR

    if is_running_mtp; then
        echo -e "Notice：\033[33mMTProxyAlready running, please do not start again!\033[0m"
    else
        do_kill_process
        do_check_system_datetime_and_update

        local command=$(get_run_command)
        echo $command
        while true
        do
            {
                sleep 2
                info_mtp "ingore"
            } &
            $command >/dev/null 2>&1
            echo "Process detected closed, restarting...!!!"
            sleep 2
        done
    fi
}

debug_mtp() {
    cd $WORKDIR

    echo "Currently running in debug mode："
    echo -e "\tYou can cancel anytime using Ctrl+C"

    do_kill_process
    do_check_system_datetime_and_update

    local command=$(get_run_command)
    echo $command
    $command

}

stop_mtp() {
    local pid=$(cat $pid_file)
    kill -9 $pid

    if is_pid_exists $pid; then
        echo "Failed to stop the task"
    fi
}

reinstall_mtp() {
    cd $WORKDIR
    if [ -f "./mtp_config" ]; then
        while true; do
            default_keep_config="y"
            echo -e "Do you want to keep the configuration file?? "
            read -p "y: Keep , n: 不Keep (默认: ${default_keep_config}):" input_keep_config
            [ -z "${input_keep_config}" ] && input_keep_config=${default_keep_config}

            if [[ "$input_keep_config" == "y" ]] || [[ "$input_keep_config" == "n" ]]; then
                if [[ "$input_keep_config" == "n" ]]; then
                    rm -f mtp_config
                fi
                break
            fi
            echo -e "[\033[33mError\033[0m] 输入Error， 请输入 y / n"
        done
    fi

    if [ ! -f "./mtp_config" ]; then 
        do_install_basic_dep
        do_config_mtp
    fi

    do_install
    run_mtp
}

param=$1

if [[ "start" == $param ]]; then
    echo "About to start the script"
    run_mtp
elif [[ "daemon" == $param ]]; then
    echo "About to start the script(守护进程)"
    daemon_mtp
elif [[ "stop" == $param ]]; then
    echo "About to stop the script"
    stop_mtp
elif [[ "debug" == $param ]]; then
    echo "即将：Run in debug mode"
    debug_mtp
elif [[ "restart" == $param ]]; then
    stop_mtp
    run_mtp
    debug_mtp
elif [[ "reinstall" == $param ]]; then
    reinstall_mtp
elif [[ "build" == $param ]]; then
    arch=$(get_architecture)
    if [[ "$arch" == "amd64" ]]; then
        build_mtproto 1
    fi
    
     build_mtproto 2
else
    if ! is_installed; then
        echo "MTProxyTLS one-click installation script"
        print_line
        echo -e "Configuration file not found, guiding you to create one!" && print_line

        do_install_basic_dep
        do_config_mtp
        do_install
        run_mtp
    else
        [ ! -f "$WORKDIR/mtp_config" ] && do_config_mtp
        echo "MTProxyTLS one-click installation script"
        print_line
        info_mtp
        print_line
        echo -e "Script source：https://github.com/ellermister/mtproxy"
        echo -e "Configuration file: $WORKDIR/mtp_config"
        echo -e "Uninstall method: simply delete all files in the current directory"
        echo "Usage:"
        echo -e "\tStart service\t bash $0 start"
        echo -e "\tRun in debug mode\t bash $0 debug"
        echo -e "\tStop service\t bash $0 stop"
        echo -e "\tRestart service\t bash $0 restart"
        echo -e "\tReinstall proxy program bash $0 reinstall"
    fi
fi
