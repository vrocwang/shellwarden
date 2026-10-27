# ShellWarden OSC 133 shell integration (bash / zsh)
#
# 用法（在当前 shell 里 source 一次）：
#   source scripts/shellwarden-integration.sh
#
# 只对 bash / zsh 生效；其他 shell 不发送，避免语法错误。
# 命令文本通过 OSC 1337 发给终端，由 ShellWarden 在服务端脱敏后写入审计。

if [ -z "${__SW_INTEGRATED:-}" ]; then
__SW_INTEGRATED=1

if [ -n "${ZSH_VERSION:-}" ]; then
  __sw_precmd() { printf '\033]133;D;%s\007' "$?"; }
  __sw_preexec() {
    printf '\033]133;C\007'
    printf '\033]1337;ShellWarden;cmd;%s\007' "$(printf '%s' "$1" | base64 | tr -d '\n')"
  }
  precmd_functions+=(__sw_precmd)
  preexec_functions+=(__sw_preexec)
  PS1=$'%{\e]133;A\a%}'"$PS1"$'%{\e]133;B\a%}'
elif [ -n "${BASH_VERSION:-}" ]; then
  __sw_pc() {
    local e=$?
    local c
    c=$(HISTTIMEFORMAT= history 1 2>/dev/null | sed 's/^ *[0-9]* *//')
    printf '\033]1337;ShellWarden;cmd;%s\007' "$(printf '%s' "$c" | base64 | tr -d '\n')"
    printf '\033]133;D;%s\007' "$e"
  }
  PROMPT_COMMAND="__sw_pc${PROMPT_COMMAND:+;$PROMPT_COMMAND}"
  PS0=$'\033]133;C\007'
  PS1='\[\e]133;A\a\]'"$PS1"'\[\e]133;B\a\]'
fi
fi
