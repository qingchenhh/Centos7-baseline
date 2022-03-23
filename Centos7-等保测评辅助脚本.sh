#/bin/bash
# author:清晨

echo -e "\n\033[34m================================\033[0m"
echo -e "\033[34m> Linux 等保辅助检查脚本。\033[0m"
echo -e "\033[34m> 适用范围：Centos7.x\033[0m"
echo -e "\033[34m> by 清晨\033[0m"
echo -e "\033[34m================================\n\033[0m"

[ $(id -u) -ne 0 ] && echo -e "\033[31m[-] 请用root用户执行此脚本！\033[0m" && exit 1
n=$(echo)
os_info=$(([ -f /etc/centos-release ] && echo `cat /etc/centos-release`) || ([ -f /etc/redhat-release ] && echo `cat /etc/redhat-release`) || echo -e "\033[31m[-] 您的系统可能不是Centos7！\033[0m")

echo "当前系统版本：${os_info}"
echo "当前系统内核版本：`uname -a`" 
echo "当前系统时间：$(date +"%Y-%m-%d %H:%M:%S")"
echo "当前系统CPU使用情况：$(top -n 1 | \grep "%Cpu")"
echo "当前系统内存使用情况：$(top -n 1 | \grep "Mem :")"
echo "当前系统语言环境：$(echo $LANG)"

if [ "$(echo $os_info | grep "您的系统可能不是Centos7")" != "$n" ];then
	echo -e "\n\033[31m[-] 执行可能会报错! 关键是配置文件和部分服务名不同结果可能是错的！\n\033[0m"
	echo -e "\033[31m[-] 请在Centos7.x上执行此脚本！\033[0m"
	exit 1
fi

# echo -e "\033[34m[*] 开始最基础的基线检查！\033[0m"
echo -e "\033[34m[*] 检查是否存在危险的SUID程序。\033[0m"
suid=$(find / -perm -u=s -type f 2>/dev/null)
[ "$(echo $suid | grep '/ab ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：ab。\033[0m"
[ "$(echo $suid | grep '/agetty ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：agetty。\033[0m"
[ "$(echo $suid | grep '/ar ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：ar。\033[0m"
[ "$(echo $suid | grep '/arp ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：arp。\033[0m"
[ "$(echo $suid | grep '/as ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：as。\033[0m"
[ "$(echo $suid | grep '/awk ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：awk。\033[0m"
[ "$(echo $suid | grep '/base32 ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：base32。\033[0m"
[ "$(echo $suid | grep '/base64 ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：base64。\033[0m"
[ "$(echo $suid | grep '/basenc ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：basenc。\033[0m"
[ "$(echo $suid | grep '/bash ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：bash。\033[0m"
[ "$(echo $suid | grep '/bzip2 ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：bzip2。\033[0m"
[ "$(echo $suid | grep '/capsh ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：capsh。\033[0m"
[ "$(echo $suid | grep '/cat ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：cat。\033[0m"
[ "$(echo $suid | grep '/chmod ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：chmod。\033[0m"
[ "$(echo $suid | grep '/chown ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：chown。\033[0m"
[ "$(echo $suid | grep '/column ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：column。\033[0m"
[ "$(echo $suid | grep '/csh ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：csh。\033[0m"
[ "$(echo $suid | grep '/curl ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：curl。\033[0m"
[ "$(echo $suid | grep '/cut ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：cut。\033[0m"
[ "$(echo $suid | grep '/dash ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：dash。\033[0m"
[ "$(echo $suid | grep '/date ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：date。\033[0m"
[ "$(echo $suid | grep '/dd ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：dd。\033[0m"
[ "$(echo $suid | grep '/diff ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：diff。\033[0m"
[ "$(echo $suid | grep '/docker ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：docker。\033[0m"
[ "$(echo $suid | grep '/env ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：env。\033[0m"
[ "$(echo $suid | grep '/file ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：file。\033[0m"
[ "$(echo $suid | grep '/find ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：find。\033[0m"
[ "$(echo $suid | grep '/grep ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：grep。\033[0m"
[ "$(echo $suid | grep '/gzip ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：gzip。\033[0m"
[ "$(echo $suid | grep '/head ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：head。\033[0m"
[ "$(echo $suid | grep '/iconv ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：iconv。\033[0m"
[ "$(echo $suid | grep '/ip ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：ip。\033[0m"
[ "$(echo $suid | grep '/join ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：join。\033[0m"
[ "$(echo $suid | grep '/ksh ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：ksh。\033[0m"
[ "$(echo $suid | grep '/less ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：less。\033[0m"
[ "$(echo $suid | grep '/look ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：look。\033[0m"
[ "$(echo $suid | grep '/make ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：make。\033[0m"
[ "$(echo $suid | grep '/more ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：more。\033[0m"
[ "$(echo $suid | grep '/mv ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：mv。\033[0m"
[ "$(echo $suid | grep '/nmap ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：nmap。\033[0m"
[ "$(echo $suid | grep '/node ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：node。\033[0m"
[ "$(echo $suid | grep '/openssl ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：openssl。\033[0m"
[ "$(echo $suid | grep '/perl ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：perl。\033[0m"
[ "$(echo $suid | grep '/php ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：php。\033[0m"
[ "$(echo $suid | grep '/sed ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：sed。\033[0m"
[ "$(echo $suid | grep '/ssh-keygen ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：ssh-keygen。\033[0m"
[ "$(echo $suid | grep '/sort ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：sort。\033[0m"
[ "$(echo $suid | grep '/sqlite3 ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：sqlite3。\033[0m"
[ "$(echo $suid | grep '/systemctl ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：systemctl。\033[0m"
[ "$(echo $suid | grep '/tac ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：tac。\033[0m"
[ "$(echo $suid | grep '/tail ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：tail。\033[0m"
[ "$(echo $suid | grep '/time ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：time。\033[0m"
[ "$(echo $suid | grep '/uniq ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：uniq。\033[0m"
[ "$(echo $suid | grep '/vim ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：vim。\033[0m"
[ "$(echo $suid | grep '/wc ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：wc。\033[0m"
[ "$(echo $suid | grep '/watch ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：watch。\033[0m"
[ "$(echo $suid | grep '/wget ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：wget。\033[0m"
[ "$(echo $suid | grep '/xargs ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：xargs。\033[0m"
[ "$(echo $suid | grep '/zsh ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：zsh。\033[0m"
[ "$(echo $suid | grep '/xxd ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：xxd。\033[0m"
[ "$(echo $suid | grep '/view ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：view。\033[0m"
[ "$(echo $suid | grep '/tee ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：tee。\033[0m"
[ "$(echo $suid | grep '/tclsh ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：tclsh。\033[0m"
[ "$(echo $suid | grep '/strings ')" != "$n" ] && echo -e "\033[31m[-] 存在危险的SUID程序：strings。\033[0m"

echo -e "\n\033[34m[*] 身份鉴别 a)项 ==============\033[0m"
# echo -e "\033[34m[*] 检查除root外uid为0的用户。\033[0m"
id0=$(cat /etc/passwd | awk -F: '($3 == 0)&&($1 != "root") { print $1 }')
for i in $id0;do
	echo -e "\033[31m[-] 存在id为0的非root用户，用户名为$i。\033[0m"
done

# echo -e "\033[34m[*] ===============等保相关配置内容获取===============\033[0m"

# 获取passwd文件中的用户数量。
user_number=$(cat /etc/passwd | wc -l)
# 获取shadow文件中的用户数量。
user_number1=$(cat /etc/shadow | wc -l)
# 获取passwd所有用户
all_user_name=$(awk -F: '{print $1}' /etc/passwd)
# 获取shadow所有用户
all_user_name1=$(awk -F: '{print $1}' /etc/shadow)

# 判断passwd中的用户数量与shadow文件中的用户数量是否相等。
if [ $user_number -gt $user_number1 ];then
	echo -e "\033[31m[-] passwd文件比shadow文件的用户多，请核查。\033[0m"
	echo -e "\033[31m[*] passwd和shadow文件的用户数量分别为:$user_number,$user_number1。\033[0m"
	for i in $all_user_name; do
		num=0
		for j in $all_user_name1;do
			let num+=1
			if [ "$i" == "$j" ] ;then
				break
			elif [ $num -eq $user_number1 ];then
				echo -e "\033[31m[-] passwd文件多出的用户:$i。\033[0m"
			fi
		done
	done
elif [ $user_number -lt $user_number1 ]; then
	echo -e "\033[31m[-] shadow文件比passwd文件的用户多，请核查。\033[0m"
	echo -e "\033[31m[*] passwd和shadow文件的用户数量分别为:$user_number,$user_number1。\033[0m"
	for i in $all_user_name1; do
		num=0
		for j in $all_user_name;do
			let num+=1
			if [ "$i" == "$j" ];then
				break
			elif [ $num -eq $user_number ];then
				echo -e "\033[31m[-] shadow文件多出的用户:$i。\033[0m"
			fi
		done
	done
fi

# echo "是否存在空口令用户。"
passs_pace=$(cat /etc/shadow | awk -F: '($2 == "" ) { print $1 }')

[ "$passs_pace" == "$n" ] && echo "系统登录时需要进行身份鉴别。" || echo -e "\033[31m[-] 部分用户登录系统时不需要进行身份鉴别。\033[0m"

all_user_name1=$(echo ${all_user_name/'\n'/' '} | sed 's/ /'、'/g')
echo "系统共${user_number}个用户，用户列表如下：${all_user_name1}"

# [ $(cat /etc/passwd | awk -F: '{print $3}' | sort | uniq -c | awk '($1>1) {print $2}') == "" ] && echo "每个用户的身份标识都具有唯一性。" || echo -e "\033[31m[-] 用户uid号有重复，请手动核查。\033[0m"

no_only_uid=$(cat /etc/passwd | awk -F: '{print $3}' | sort | uniq -c | awk '($1>1) {print $2}')

if [ "$no_only_uid" != "$n" ]; then
	for i in $no_only_uid;do
		echo -e "\033[31m[-] 用户uid号有重复，重复的uid为：$i。\033[0m"
	done
else
	echo "每个用户的身份标识都具有唯一性。"
fi

if [ "$passs_pace" != "$n" ]; then
	for i in $passs_pace;do
		echo -e "\033[31m[-] 存在空口令用户，用户名为$i。\033[0m"
	done
else
	echo "核查用户列表，没有空口令的用户。"
fi

if [ -f /etc/security/pwquality.conf ] ;then
	pwquality1=$(grep -v "^#" /etc/security/pwquality.conf | grep -v "^$")
	if [ "$pwquality1" != "$n" ];then
		minlen1=$(echo "${pwquality1}" | grep minlen | awk -F[=] '{print $2}' | sed 's/^[ ]*//g')
		dcredit1=$(echo "${pwquality1}" | grep dcredit | awk -F[=] '{print $2}' | sed 's/^[ ]*//g')
		ucredit1=$(echo "${pwquality1}" | grep ucredit | awk -F[=] '{print $2}' | sed 's/^[ ]*//g')
		lcredit1=$(echo "${pwquality1}" | grep lcredit | awk -F[=] '{print $2}' | sed 's/^[ ]*//g')
		ocredit1=$(echo "${pwquality1}" | grep ocredit | awk -F[=] '{print $2}' | sed 's/^[ ]*//g')
	fi
fi

if [ -f /etc/security/pwquality.conf ]; then
	pwquality2=$(grep "pam_pwquality.so" /etc/pam.d/system-auth | grep -v "^$")
	if [ "$pwquality2" != "$n" ];then
		minlen2=$(echo "${pwquality2}" | grep -o "minlen=[0-9][0-9]\?" | awk -F[=] '{print $2}' | sed 's/^[ ]*//g')
		dcredit2=$(echo "${pwquality2}" | grep -o "dcredit=[-]\?[0-9]" | awk -F[=] '{print $2}' | sed 's/^[ ]*//g')
		ucredit2=$(echo "${pwquality2}" | grep -o "ucredit=[-]\?[0-9]" | awk -F[=] '{print $2}' | sed 's/^[ ]*//g')
		lcredit2=$(echo "${pwquality2}" | grep -o "lcredit=[-]\?[0-9]" | awk -F[=] '{print $2}' | sed 's/^[ ]*//g')
		ocredit2=$(echo "${pwquality2}" | grep -o "ocredit=[-]\?[0-9]" | awk -F[=] '{print $2}' | sed 's/^[ ]*//g')
	fi
fi

([ -n $minlen1 ] || [ -n $minlen2 ]) && [ "$minlen1" != "$n" ] && minlen=$minlen1 || minlen=$minlen2
([ -n $dcredit1 ] || [ -n $dcredit2 ]) && [ "$dcredit1" != "$n" ] && dcredit=$dcredit1 || dcredit=$dcredit2
([ -n $ucredit1 ] || [ -n $ucredit2 ]) && [ "$ucredit1" != "$n" ] && ucredit=$ucredit1 || ucredit=$ucredit2
([ -n $lcredit1 ] || [ -n $lcredit2 ]) && [ "$lcredit1" != "$n" ] && lcredit=$lcredit1 || lcredit=$lcredit2
([ -n $ocredit1 ] || [ -n $ocredit2 ]) && [ "$ocredit1" != "$n" ] && ocredit=$ocredit1 || ocredit=$ocredit2
([ -n $difok1 ] || [ -n $difok2 ]) && [ "$difok1" != "$n" ] && difok=$difok1 || difok=$difok2
([ -n $retry1 ] || [ -n $retry1 ]) && [ "$retry1" != "$n" ] && retry=$retry1 || retry=$retry2

echo "密码策略核查"
echo -e "\033[33m[*] 因为该策略有些复杂，涉及的配置文件较多，并不单纯的是根据login.defs文件或者system-auth来配置的，还可能根据/etc/pam.d/sshd、/etc/pam.d/login等其他文件来配置，存在的情况较多，因此请根据实际情况手工判断该项。 \033[0m"
pass_max_days=$(grep PASS_MAX_DAYS /etc/login.defs | grep -v ^# | awk '{print $2}')
[ $pass_max_days -le 90 -a $pass_max_days -gt 0 ] && echo "密码最长有效期符合要求，最长有效期为：${pass_max_days}" || echo -e "\033[31m[-] 密码最长有效期不符合要求，最长有效期为：${pass_max_days}。\033[0m"
pass_mix_days=$(grep PASS_MIN_DAYS /etc/login.defs | grep -v ^# | awk '{print $2}')
[ $pass_mix_days -ge 6 ] && echo "密码最短有效期符合要求，最短有效期为：${pass_mix_days}" || echo -e "\033[31m[-] 密码最短有效期不符合要求，最短有效期为：${pass_mix_days}。\033[0m"
pass_mix_len=$(grep PASS_MIN_LEN /etc/login.defs | grep -v ^# | awk '{print $2}')
([ $pass_mix_len -ge 8 ] && echo "密码最小长度符合要求，密码最小长度为：${pass_mix_len}") || ([ "$minlen" != "$n" ] && echo "密码最小长度符合要求，密码最小长度为：$minlen" )|| echo -e "\033[31m[-] 密码最小长度不符合要求，密码最小长度为：${pass_mix_len}。\033[0m"
pass_warn_age=$(grep PASS_WARN_AGE /etc/login.defs | grep -v ^# | awk '{print $2}')
[ $pass_warn_age -lt $pass_max_days -a $pass_warn_age -ge 7 ] && echo "密码过期警告天数符合要求，过期警告天数为：${pass_warn_age}" || echo -e "\033[31m[-] 密码过期警告天数不符合要求，过期警告天数为：${pass_warn_age}。\033[0m"

([ "$dcredit" == "-1" ] && echo "密码策略设置至少包含一个数字。") || ([ "$dcredit" == "-2" ] && echo "密码策略设置至少包含两个数字。") || echo -e "\033[31m[-] 不符合要求，dcredit的值为：${dcredit}。\033[0m"
([ "$ucredit" == "-1" ] && echo "密码策略设置至少包含一个大写字母。") || ([ "$ucredit" == "-2" ] && echo "密码策略设置至少包含两个大写字母。")  || echo -e "\033[31m[-] 不符合要求，ucredit的值为：${ucredit}。\033[0m"
([ "$lcredit" == "-1" ] && echo "密码策略设置至少包含一个小写字母。") || ([ "$lcredit" == "-2" ] && echo "密码策略设置至少包含两个小写字母。") || echo -e "\033[31m[-] 不符合要求，lcredit的值为：${lcredit}。\033[0m"
([ "$ocredit" == "-1" ] && echo "密码策略设置至少包含一个特殊字符。") || ([ "$ocredit" == "-2" ] && echo "密码策略设置至少包含两个特殊字符。") || echo -e "\033[31m[-] 不符合要求，ocredit的值为：${ocredit}。\033[0m"


echo -e "\n\033[34m[*] 身份鉴别 b)项 ==============\033[0m"
echo -e "\033[33m[*] 因为该策略有些复杂，请根据实际情况手工判断该项。 \033[0m"
if [ -f /etc/security/pwquality.conf ]; then
	tally=$(grep "pam_tally2.so" /etc/pam.d/system-auth | grep -v ^#)
	if [ "$tally" != "$n" ];then
		deny=$(echo "${tally}" | grep -o "deny=[0-9][0-9]\?" | awk -F[=] '{print $2}' | sed 's/^[ ]*//g')
		unlock_time=$(echo "${tally}" | grep -o " unlock_time=[0-9][0-9]\?[0-9]\?[0-9]\?[0-9]\?" | awk -F[=] '{print $2}' | sed 's/^[ ]*//g')
		root_unlock_time=$(echo "${tally}" | grep -o "root_unlock_time=[0-9][0-9]\?[0-9]\?[0-9]\?[0-9]\?" | awk -F[=] '{print $2}' | sed 's/^[ ]*//g')
		even_deny_root=$(echo "${tally}" | grep even_deny_root )
	fi
fi

if [ "$deny" != "$n" ] ;then
	echo "系统设置了登录密码错误${deny}次锁定。"
	if [ "$unlock_time" != "$n" ];then
		echo "系统设置了登录密码错误后锁定${unlock_time}秒。"
	else
		echo -e "\033[31m[-] 系统没有设置登录密码错误锁定时间。\033[0m"
	fi
	if [ "$even_deny_root" != "$n" ];then
		echo "系统设置的错误锁定次数也限制了root用户。"
		if [ "$root_unlock_time" != "$n" ];then
			echo "系统设置root的登录密码错误后锁定${root_unlock_time}秒。"
		else
			echo -e "\033[31m[-] 系统没有设置root的登录密码错误后锁定的时间。\033[0m"
		fi
	else
		echo -e "\033[31m[-] 系统设置的错误锁定次数没有限制root用户。\033[0m"
	fi
else
	echo -e "\033[31m[-] 系统没有设置登录密码错误次数限制。\033[0m"
fi

timeout=$(grep TMOUT /etc/profile | grep -v ^# | awk -F[=] '{print $2}')
ClientAliveInterval=$(grep ClientAliveInterval /etc/ssh/sshd_config | grep -v ^# | awk '{print $2}')
# ClientAliveCountMax=$(grep ClientAliveCountMax /etc/ssh/sshd_config | grep -v ^# | awk '{print $2}')
if [ "$timeout" != "$n" ]; then
	echo "系统设置了账号超时时间，账号超时的时间为：$timeout"
elif [ "$ClientAliveInterval" != "$n" ];then
	echo "系统通过ssh配置文件设置了账号超时时间，超时时间为：$ClientAliveInterval"
else
	echo -e "\033[31m[-] 系统没有设置账号超时时间。\033[0m" 
fi

echo -e "\n\033[34m[*] 身份鉴别 c)项 ==============\033[0m"

ssh_is_running=$(systemctl status sshd | grep -o "Active: active (running)")
if [ "$ssh_is_running" != "$n" ]; then
	echo "系统使用SSH协议进行远程管理。"
else
	echo -e "\033[31m[-] 系统SSH服务关闭。\033[0m"
fi

# (systemctl status telnet.socket >& /dev/null) || echo "2）经现场核查，系统没有开启telnet服务。"

telnet=$(rpm -qa | grep telnet*)
telnet_port=$(netstat -an | grep ":23$")
if [ "$telnet" == "$n" -a "$telnet_port" == "$n" ]; then
	echo "系统没有开启telnet服务。"
else
	echo -e "\033[31m[-] 系统开启了telnet服务。\033[0m"
fi

echo -e "\n\033[34m[*] 身份鉴别 d)项 ==============\033[0m"
echo -e "\033[33m[*] 请根据实际情况手工判断该项。 \033[0m"

PasswordAuthentication=$(grep -v ^$ /etc/ssh/sshd_config | grep -v ^# | grep PasswordAuthentication | awk '{print $2}')

if [ "$PasswordAuthentication" == "yes" -o "$PasswordAuthentication" != "no" ]; then
	echo "根据ssh的配置，系统允许使用密码进行登录。"
else
	echo -e "\033[31m[-] 根据ssh的配置，系统禁止了使用密码进行登录。\033[0m"
fi

echo -e "\n\033[34m[*] 访问控制 a)项 ==============\033[0m"

echo "系统共${user_number}个用户，用户列表如下：${all_user_name1}"

echo -e "\033[33m[*] 请根据实际情况手工核查，是否有匿名用户或者系统用户没有被禁用的。 \033[0m"
# 获取普通用户
echo "普通用户列表如下："
users=$(awk -F: '$7=="/bin/bash" {print $1}' /etc/passwd)
echo ${users/'\n'/' '}

# 获取能登录的用户
echo "没有禁用的用户列表如下："
login_user=$(awk -F: '($2 != "*")&&($2 != "!!")&&($2 != "!") {print $1}' /etc/shadow)
echo ${login_user/'\n'/' '}

etc_w=$(find /etc/ -perm -002 -type f -exec  ls -l {} \; | grep -v /etc/uuid)
[ "$etc_w" != "$n" ] && echo -e "\033[33m[*] 系统配置文件中存在其他人拥有写权限的文件(请根据实际情况手工核查)。\033[0m" && echo -e "\033[31m[-] 其他人拥有写权限的文件列表如下：\n ${etc_w}\033[0m"


echo -e "\n\033[34m[*] 访问控制 b)项 ==============\033[0m"
echo -e "\033[33m[*] 请根据实际情况手工核查用户情况。 \033[0m"
echo "系统共${user_number}个用户，用户列表如下：${all_user_name1}"
# 获取普通用户
echo "普通用户列表如下："
echo ${users/'\n'/' '}

# 获取能登录的用户
echo "没有禁用的用户列表如下："
echo ${login_user/'\n'/' '}
PermitRootLogin=$(grep PermitRootLogin /etc/ssh/sshd_config | grep -v "^#" | awk '{print $2}')
[ "$PermitRootLogin" != "no" ] && echo -e "\033[31m[-] 未设置PermitRootLogin参数为no。\033[0m" || echo "已设置PermitRootLogin参数为no。"

echo -e "\n\033[34m[*] 访问控制 c)项 ==============\033[0m"
echo -e "\033[33m[*] 请根据实际情况手工核查是否存在多余的、过期的账户，避免共享账户的存在。 \033[0m"
echo "1) 系统共${user_number}个用户，用户列表如下：${all_user_name1}"
# 获取普通用户
echo "普通用户列表如下："
echo ${users/'\n'/' '}

# 获取能登录的用户
echo "没有禁用的用户列表如下："
echo ${login_user/'\n'/' '}

echo -e "\n\033[34m[*] 访问控制 d)项 ==============\033[0m"
echo -e "\033[33m[*] 请根据实际情况手工核查sudo权限是否分配合理,sudo权限配置如下：。 \033[0m"
grep -v ^$ /etc/sudoers | grep -v ^# | grep -v Defaults

echo -e "\n\033[34m[*] 访问控制 e)项 ==============\033[0m"
echo -e "\033[33m[*] 该项请人工核对。 \033[0m"

echo -e "\n\033[34m[*] 访问控制 f)项 ==============\033[0m"
echo "系统的访问控制策略的主体为用户，客体为文件、进程和命令。"

echo -e "\n\033[34m[*] 访问控制 g)项 ==============\033[0m"
selinux=$(grep "SELINUX=" /etc/selinux/config | grep -v ^# | awk -F[=] '{print $2}')
selinux_type=$(grep "SELINUXTYPE=" /etc/selinux/config | grep -v ^# | awk -F[=] '{print $2}')
if [ "$selinux" != "disabled" ];then
	echo "Linux 操作系统开启了SELinux服务，SELinux的工作模式为：${selinux}，SELinux的type为：${selinux_type}。"
else
	echo -e "\033[31m[-] 系统没有强制访问控制措施。\033[0m"
fi

echo -e "\n\033[34m[*] 安全审计 a)项 ==============\033[0m"
echo -e "\033[33m[*] 请根据实际情况手工核查审计策略是否符合要求。 \033[0m"
auditd_is_running=$(systemctl status auditd.service | grep -o "Active: active (running)")
rsyslog_is_running=$(systemctl status rsyslog.service | grep -o "Active: active (running)")
if [ "$auditd_is_running" != "$n" ]; then
	echo "系统有启用安全审计功能，auditd.service服务为running状态。"
	if [ "$rsyslog_is_running" != "$n" ]; then
		echo "rsyslog.service服务为running状态。"
	else
		echo -e "\033[31m[-] rsyslog.service服务没有开启。\033[0m"
	fi

else
	echo -e "\033[31m[-] 系统没有启用安全审计功能，auditd.service服务没有开启。\033[0m"
fi
echo "核查rsyslog.conf文件，存在以下配置："
cat /etc/rsyslog.conf | grep -v ^# | grep -v ^$
echo
echo "使用auditctl -l核查运行的审计规则，结果如下:"
auditctl -l 
echo
echo "核查/etc/audit/audit.rules文件，审计规则配置如下："
cat /etc/audit/audit.rules 2>/dev/null
echo
echo "通过aureport -i命令查看审计报告总览，结果如下："
aureport -i | grep -v ^#
echo -e "\033[33m[*] 为了严谨性，以便人工核对。增加了一下审计配置文件的获取。\033[0m"
echo -e "\033[33m[*] /etc/audit/auditd.conf文件内容如下:\033[0m"
cat /etc/audit/auditd.conf | grep -v ^# | grep -v ^$
echo -e "\033[33m[*] /etc/audit/audit-stop.rules文件内容如下:\033[0m"
cat /etc/audit/audit-stop.rules | grep -v ^# | grep -v ^$
echo -e "\033[33m[*] /etc/audit/rules.d/audit.rules文件内容如下:\033[0m"
cat /etc/audit/rules.d/audit.rules | grep -v ^# | grep -v ^$

echo -e "\n\033[34m[*] 安全审计 b)项 ==============\033[0m"
echo -e "\033[33m[*] 请根据实际情况手工核查审计范围。 \033[0m"
echo "最后20条audit.log文件内容如下:"
tail -20 /var/log/audit/audit.log
echo -e "\033[33m[*] 请根据核查系统时间与网络时间是否一直。 \033[0m"
echo "当前系统时间：$(date +"%Y-%m-%d %H:%M:%S")"
info_syslog=$(grep "\*\.info;mail\.none;authpriv\.none;cron\.none" /etc/rsyslog.conf | grep -v ^#)
[ "$info_syslog" == "$n" ] && echo -e "\033[33m[*] rsyslog.conf配置的日志信息不足够详细。缺少*.info;mail.none;authpriv.none;cron.none /var/log/messages的配置(人工核查)。\033[0m"

echo -e "\n\033[34m[*] 安全审计 c)项 ==============\033[0m"
log_w=$(find /var/log/ -perm -002 -exec ls -l {} \;)
[ "$etc_w" != "$n" ] && echo -e "\033[33m[*] 系统日志文件中存在其他人拥有写权限的文件(请根据实际情况手工核查)。\033[0m" && echo -e "\033[31m[-] 其他人拥有写权限的文件列表如下：\n ${log_w}\033[0m"

echo "日志文件权限如下："
ls -ld /var/log/audit /var/log /etc/audit
ls -l /etc/rsyslog.conf

syslog=$(grep "\*\.\* @" /etc/rsyslog.conf | grep -v ^#)
[ "$syslog" != "$n" ] && echo "系统配置了日志服务器进行日志记录的备份，具体配置为：${syslog}" || echo -e "\033[31m[-] 系统没有配置日志服务器进行日志记录的备份\033[0m"

echo -e "\n\033[34m[*] 安全审计 d)项 ==============\033[0m"

is_root_auditd=$(ps -ef|grep "/auditd" | grep -v "grep")
is_root_kauditd=$(ps -ef|grep "kauditd" | grep -v "grep")
if [ "$(echo $is_root_auditd | awk '{print $1}')" == "root" ];then
	echo "审计进程由root启动，普通用户无法中断。"
	echo $is_root_auditd
else
	echo -e "\033[31m[-] 审计进程不是由root启动。\033[0m"
	echo -e "\033[31m[-] $is_root_auditd\033[0m"
fi
if [ "$(echo $is_root_kauditd | awk '{print $1}')" == "root" ];then
	echo "审计进程的守护进程由root启动，普通用户无法中断。"
	echo $is_root_kauditd
else
	echo -e "\033[31m[-] 审计进程的守护进程不是由root启动。\033[0m"
	echo -e "\033[31m[-] $is_root_kauditd\033[0m"
fi


echo -e "\n\033[34m[*] 入侵防范 a)项 ==============\033[0m"
rpm_num=$(rpm -qa | wc -l)
echo "操作系统中安装的程序包和组件共${rpm_num}项。"
echo -e "\033[33m[*] 请使用rpm -qa或者yum list installed命令来核查安装的软件包是否是必须的。 \033[0m"

echo -e "\n\033[34m[*] 入侵防范 b)项 ==============\033[0m"
echo -e "\033[33m[*] 请核查是否开启了不必要的服务。 \033[0m"
systemctl list-unit-files | \grep enabled
echo -e "\033[33m[*] 请核查是否开启了不必要的端口。 \033[0m"
netstat -ntlp

echo -e "\n\033[34m[*] 入侵防范 c)项 ==============\033[0m"
echo -e "\033[33m[*] 请根据实际情况手工核查是否限制远程管理终端的网络地址，限制的地址段是否合理。 \033[0m"
echo "/etc/hosts.deny文件的内容如下："
cat /etc/hosts.deny | grep -v ^$ | grep -v ^#
echo "/etc/hosts.allow文件的内容如下："
cat  /etc/hosts.allow | grep -v ^$ | grep -v ^#

iptables_is_running=$(systemctl status iptables.service 2>/dev/null | grep -o "Active: active (running)")
firewalld_is_running=$(systemctl status firewalld.service 2>/dev/null | grep -o "Active: active (running)" )
iptables_flag=0
firewalld_flag=0
if [ "$iptables_is_running" != "$n" ]; then
	echo "iptables运行，iptables策略如下："
	iptables -L -n
	iptables_flag=1
fi
if [ "$firewalld_is_running" != "$n" ]; then
	echo "firewalld运行，firewall策略如下："
	firewall-cmd --list-all
	echo "firewall默认区："
	firewall-cmd --get-default-zone
	firewalld_flag=1
fi
[ $iptables_flag -ne 0 -a $firewalld_flag -ne 0 ] && echo -e "\033[31m[-] 系统防火墙并没有开启。\033[0m"

echo -e "\n\033[34m[*] 入侵防范 d)项 ==============\033[0m"
echo "根据 GB/T28448 的规定，本项测评指标的测评对象不包含服务器。"

echo -e "\n\033[34m[*] 入侵防范 e)项 ==============\033[0m"
echo -e "\033[33m[*] 请做系统漏洞扫描，并根据扫描情况判断。 \033[0m"
echo "系统安装的补丁情况如下："
rpm -qa | grep patch

echo -e "\n\033[34m[*] 入侵防范 f)项 ==============\033[0m"
echo -e "\033[33m[*] 请手工核查是否装有主机IPS或者网络IPS。 \033[0m"

echo -e "\n\033[34m[*] 恶意代码防范 ==============\033[0m"
echo -e "\033[33m[*] 请手工核查是否安装防病毒软件。 \033[0m"

echo -e "\n\033[34m[*] 可信验证 ==============\033[0m"
echo -e "\033[33m[*] 请手工核查是否有可信验证。 \033[0m"

echo -e "\n\033[34m[*] 数据完整性 a)项 ==============\033[0m"
echo -e "\033[33m[*] 请手工核查重要数据在传输过程中的完整性是否得到保障。 \033[0m"

if [ "$ssh_is_running" != "$n" ]; then
	echo "系统有使用数据传输完整性保障技术，使用的技术为：SSH传输。"
else
	echo -e "\033[31m[-] 系统SSH服务关闭。\033[0m"
fi

echo -e "\n\033[34m[*] 数据完整性 b)项 ==============\033[0m"
echo -e "\033[33m[*] 请手工核查重要数据在存储过程中的完整性是否得到保障。 \033[0m"

echo -e "\n\033[34m[*] 数据保密性 a)项 ==============\033[0m"
echo "根据 GB/T28448 的规定，本项测评指标的测评对象不包含服务器。"

echo -e "\n\033[34m[*] 数据保密性 b)项 ==============\033[0m"
echo -e "\033[33m[*] 请手工核查重要数据在存储过程中的保密性是否得到保障。 \033[0m"

echo -e "\n\033[34m[*] 数据备份恢复 a)项 ==============\033[0m"
echo -e "\033[33m[*] 该项请人工核对。 \033[0m"

echo -e "\n\033[34m[*] 数据备份恢复 b)项 ==============\033[0m"
echo -e "\033[33m[*] 该项请人工核对。 \033[0m"

echo -e "\n\033[34m[*] 数据备份恢复 c)项 ==============\033[0m"
echo -e "\033[33m[*] 该项请人工核对。 \033[0m"

echo -e "\n\033[34m[*] 剩余信息保护 a)项 ==============\033[0m"
echo "CentOS7系统该项默认符合"

echo -e "\n\033[34m[*] 剩余信息保护 b)项 ==============\033[0m"
echo "CentOS7系统该项默认符合"

echo -e "\n\033[34m[*] 个人信息保护 a)项 ==============\033[0m"
echo "根据 GB/T28448 的规定，本项测评指标的测评对象不包含服务器。"

echo -e "\n\033[34m[*] 个人信息保护 b)项 ==============\033[0m"
echo "根据 GB/T28448 的规定，本项测评指标的测评对象不包含服务器。"


echo -e "\n\033[34m[*] ==========================================\033[0m"
echo -e "\n\033[34m[*] 为了方便后续人工核查，将会把以上核查的对象原始内容存储到文件中。 \033[0m"
echo "==============/etc/passwd文件==============" > ./res_config.log
cat /etc/passwd 2>/dev/null >> ./res_config.log
echo "==============/etc/shadow文件==============" >> ./res_config.log
cat /etc/shadow 2>/dev/null >> ./res_config.log
echo "==============/etc/login.defs==============" >> ./res_config.log
cat /etc/login.defs 2>/dev/null >> ./res_config.log
echo "==============/etc/pam.d/system-auth==============" >> ./res_config.log
cat /etc/pam.d/system-auth 2>/dev/null >> ./res_config.log
echo "==============/etc/security/pwquality.conf==============" >> ./res_config.log
cat /etc/security/pwquality.conf 2>/dev/null >> ./res_config.log
echo "==============/etc/pam.d/login==============" >> ./res_config.log
cat /etc/pam.d/login 2>/dev/null >> ./res_config.log
echo "==============sshd服务状态==============" >> ./res_config.log
systemctl status sshd 2>/dev/null >> ./res_config.log
echo "==============/etc/profile==============" >> ./res_config.log
cat /etc/profile 2>/dev/null >> ./res_config.log
echo "==============/etc/ssh/sshd_config==============" >> ./res_config.log
cat /etc/ssh/sshd_config 2>/dev/null >> ./res_config.log
echo "==============/etc/sudoers==============" >> ./res_config.log
cat /etc/sudoers 2>/dev/null >> ./res_config.log
echo "==============/etc/selinux/config==============" >> ./res_config.log
cat /etc/selinux/config 2>/dev/null >> ./res_config.log
echo "==============auditd服务状态==============" >> ./res_config.log
systemctl status auditd.service 2>/dev/null >> ./res_config.log
echo "==============rsyslog服务状态==============" >> ./res_config.log
systemctl status rsyslog.service 2>/dev/null >> ./res_config.log
echo "==============/etc/rsyslog.conf==============" >> ./res_config.log
cat /etc/rsyslog.conf 2>/dev/null >> ./res_config.log
echo "==============auditctl -l==============" >> ./res_config.log
auditctl -l 2>/dev/null >> ./res_config.log
echo "==============/etc/audit/audit.rules==============" >> ./res_config.log
cat /etc/audit/audit.rules 2>/dev/null >> ./res_config.log
echo "==============aureport -i==============" >> ./res_config.log
aureport -i 2>/dev/null >> ./res_config.log
echo "==============/etc/audit/auditd.conf==============" >> ./res_config.log
cat /etc/audit/auditd.conf 2>/dev/null >> ./res_config.log
echo "==============/etc/audit/audit-stop.rules==============" >> ./res_config.log
cat /etc/audit/audit-stop.rules 2>/dev/null >> ./res_config.log
echo "==============/etc/audit/rules.d/audit.rules==============" >> ./res_config.log
cat /etc/audit/rules.d/audit.rules 2>/dev/null >> ./res_config.log
echo "==============当前系统时间==============" >> ./res_config.log
echo "当前系统时间：$(date +"%Y-%m-%d %H:%M:%S")" 2>/dev/null >> ./res_config.log
echo "==============/var/log/audit/audit.log最后20行内容==============" >> ./res_config.log
tail -20 /var/log/audit/audit.log 2>/dev/null >> ./res_config.log
echo "==============/var/log其他人可写的文件==============" >> ./res_config.log
find /var/log/ -perm -002 -exec ls -l {} \; >> ./res_config.log
echo "==============/var/log/audit /var/log /etc/audit目录权限==============" >> ./res_config.log
ls -ld /var/log/audit /var/log /etc/audit 2>/dev/null >> ./res_config.log
echo "==============/etc/rsyslog.conf文件权限==============" >> ./res_config.log
ls -l /etc/rsyslog.conf 2>/dev/null >> ./res_config.log
echo "==============auditd进程情况==============" >> ./res_config.log
ps -ef 2>/dev/null |grep "auditd" | grep -v "grep" >> ./res_config.log
echo "==============rpm查看已安装的软件包==============" >> ./res_config.log
rpm -qa 2>/dev/null >> ./res_config.log
echo "==============yum查已安装的软件包==============" >> ./res_config.log
yum list installed 2>/dev/null >> ./res_config.log
echo "==============自启动的服务==============" >> ./res_config.log
systemctl list-unit-files 2>/dev/null | grep enabled >> ./res_config.log
echo "==============ps aux查看进程情况==============" >> ./res_config.log
ps aux 2>/dev/null >> ./res_config.log
echo "==============ps -ef查看进程情况==============" >> ./res_config.log
ps -ef 2>/dev/null >> ./res_config.log
echo "==============端口监听情况==============" >> ./res_config.log
netstat -ntlp 2>/dev/null >> ./res_config.log
echo "==============/etc/hosts.deny==============" >> ./res_config.log
cat /etc/hosts.deny 2>/dev/null >> ./res_config.log
echo "==============/etc/hosts.allow==============" >> ./res_config.log
cat  /etc/hosts.allow 2>/dev/null >> ./res_config.log
echo "==============iptables服务状态==============" >> ./res_config.log
systemctl status iptables.service 2>/dev/null >> ./res_config.log
echo "==============firewalld服务状态==============" >> ./res_config.log
systemctl status firewalld.service 2>/dev/null >> ./res_config.log
echo "==============iptables策略详情==============" >> ./res_config.log
iptables -L -n 2>/dev/null >> ./res_config.log
echo "==============firewall-cmd策略详情==============" >> ./res_config.log
firewall-cmd --list-all 2>/dev/null >> ./res_config.log
echo "==============firewall-cmd默认域==============" >> ./res_config.log
firewall-cmd --get-default-zone 2>/dev/null >> ./res_config.log
echo "==============Linux补丁安装情况==============" >> ./res_config.log
rpm -qa 2>/dev/null | grep patch >> ./res_config.log
echo "==============拥有suid权限的可执行文件==============" >> ./res_config.log
find / -perm -u=s -type f 2>/dev/null >> ./res_config.log
# echo "==============top信息==============" >> ./res_config.log
# top -n 1 2>/dev/null >> ./res_config.log
echo "==============内存信息==============" >> ./res_config.log
free -h 2>/dev/null >> ./res_config.log
echo "==============IP地址信息==============" >> ./res_config.log
ip a 2>/dev/null >> ./res_config.log
echo "==============内核信息==============" >> ./res_config.log
uname -a 2>/dev/null >> ./res_config.log
echo "==============centos Linux版本信息==============" >> ./res_config.log
cat /etc/centos-release 2>/dev/null >> ./res_config.log
echo "==============redhat Linux版本信息==============" >> ./res_config.log
cat /etc/redhat-release 2>/dev/null >> ./res_config.log

echo -e "\n\033[32m \033[1m"

echo -e "\n\033[32m[+] 同时以上使用的原始内容保存了一份到当前目录下的res_config.log文件中，可以使用它和脚本的结果进行人工核对，记得下载！ \033[1m"

echo -e "\n\033[32m[+] 请核对以上结果！！！ \033[1m"

echo -e "\n\033[32m[+] 程序执行完毕！感谢您的使用！ \033[1m"

echo -e "\n\033[32m \033[0m"
