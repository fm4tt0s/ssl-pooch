#!/usr/bin/env bash
#
# author    : Felipe Mattos
# scm       : https://github.com/fm4tt0s/ssl-pooch
# date      : 07-May-21
# updated   : 15-Jun-21
#
# version   : 1.6
    _my_version="1.6"
# name:     : ssl-pooch [woof-woof]
    _my_name="ssl-pooch [woof-woof]"
#
# language  : bash
# purpose   : check/monitor/test SSL certs
# remarks   : NA
#
# tested on : 
#   RHEL, Maipo 8, GNU bash, version 4.2.46
#   CentOS, Core 7, GNU bash, version 4.2.46
#   Ubuntu, Focal Fossa 20.04 LTS, GNU bash, version 5.0.17
#   Alpine, 3.7.1, GNU bash, version 4.4.19
#   MacOS, BigSur 11, GNU bash, version 3.2.57
#
# exit codes:
#   0       : mellow, clean/normal exit
#   3       : missing dependency/var not set
#   5       : malformed command
#   8       : interrupted, INT caught
#   13      : input/output/file error
#   15      : FQDN file list related error
#
# change log
#   - 0.1, Felipe Mattos, initial
#   - 0.2, Felipe Mattos, added 'timeout' function for MacOS or Unix, depending on perl.
#   - 0.3, Felipe Mattos, made temp files more 'meaningful' - as if it matters. 
#   - 0.4, Felipe Mattos, fixed bad coding. made 443 default port in case it's not provided.
#   - 0.5, Felipe Mattos, added support for extra fields from cert.
#   - 0.6, Felipe Mattos, added output types, csv/json/html.
#   - 0.7, Felipe Mattos, added support for sending email alert.
#   - 0.8, Felipe Mattos, added order-by and filter capabilities; CA Wily APM output type; 
#       handle all exits thru die function.
#   - 0.9, Felipe Mattos, added statsd/prometheus/cloudwatch/graphite/esapm output; created 
#       a 'manual' (maybe it gone too far) and a quick help message.
#   - 1.0, Felipe Mattos, added FQDN file list validation; added support to use static fields
#       when running against a list.
#   - 1.1, Felipe Mattos, added support to parse SAML IdP Metadata XML certficate files;
#       added (somehwhat) support to inject results to instrumentation endpoint; added support to grab 
#       certificate from a URL as a downloable resource; accepts proxy for openssl, when available, and 
#       when using it, tcp socket test will be ignored, cant run it over proxy.
#   - 1.2, Felipe Mattos, added support to use alternative label when running against FQDN list.
#       added support to connect to TLS mongodb. made possible to use a 'separator' on html output when 
#       running against a list. fixed 'fold' for IdP certs with long lines. fixed few HTML bad codes.
#       added option to show certificate SAN, output may get very ugly thou. 
#   - 1.3, Felipe Mattos, made possible to use telnet for sending mail - yeah a big makeshift; I needed it
#       since I want to deliver this solution on a docker container, so I dont need to waste much time 
#       dealing with postfix/mta/etc. made it seek for config file.
#   - 1.4, Felipe Mattos, added SIGINT to timeout. added '-E' option for when running against single host
#       or URL to 'Export' the endpoint certficate, spool folder set to _local_certs_path (PWD/cert_files). created a pseudo
#       'retry' for whenever an endpoint is found unreachable, so the script can seek for related local cert on
#       spool folder, controlable by custom var, _seek_local_certs being true or false; important to mention that files
#       should follow a specific naming pattern (more details on the manual), if that happens (endpoint unreachable and
#       local file found), a notation as 'local' will be put on the line to indicate data is gotten from local file. 
#       changed the 'order by' functionality so it can accept up to 2 columns to order the results - like, order by a, then b.
#   - 1.5, Felipe Mattos, added an option to show progress when running thru a list (-P), silly but some may use it. added a
#       signature variable so it can be used on the end of email body, also silly. removed telnet output from terminal. 
#       possibility to change HTML email style by changing _custom_html_style var. improved manual.
#   - 1.6, Felipe Mattos, fixed telnet mechanism for multiple rcpt addr. added a 'name' for 'email from'. changed 'export' 
#       feature to accept the arg 'c', meaning to download server cert chain in a single file or 'C' to export them in separated files.
#       added support to DER files. adder 'subject' as keyword for extra fields, yields to 'cn'. added '-d' option to dump cert details 
#       without much data handling (way too ugly but 'H' asked for it - hey 'H', howdy man?). enhanced fqdnshape, users arre mean and do
#       weird things.
#
# require   : common sense and...
    _deps=("openssl" "awk" "mktemp" "sed" "column" "fold" "wget" "bc") 

# begin custom vars
# CUSTOM VARS - change it to match your needs
# you can also use a config file like PWD/conf/config.${0}.env - in such case, the file will have
# prevalence overs variables

# SSL WARNING - days to be considered warning, anything less than it
_warning_notice=30

# openssl proxy
_openssl_proxy=""

# whether to seek or not for local certs when endpoint is unreacheable
_seek_local_certs="true"

# EMAIL VARS
# use alternative email mechanism thru telnet? if not set, sendmail will be used
# to be considered, this var should be set as: "true" "domain" "mailhost_addr" "mailhost_port"
_custom_mail_usealtmechanism=("false" "company.com" "mailhost.company.com" "25")
# recipient's email/s. split multi-addr with commas, as: addr1,addr2. 
_custom_mail_to="to@mail.com"
# sender's email
_custom_mail_from="${_my_name:0:9}@yourdomain.com"
# sender's name - if you want to show off
_custom_mail_from_name="${_my_name:0:9}"
# use different return path / reply-to?
_custom_mail_from_return_path="${_custom_mail_from}"
# email subject
_custom_mail_subject="${_my_name:0:9} - Certificate Expiration Monitor - $(date +%m-%d-%Y)"
# email signature - USE HTML code
_custom_mail_signature="<p>${_my_name} &#128054;</p>"
# custom email stylesheet for HTML emails - uncomment and change it by your will
# _custom_html_style=""

# OUTPUT SPECIFIC VARIABLES
# STATIC FIELDS
# where to position static fields 'begin' / 'end' 
_custom_static_fields_pos="begin"
# static fields names to be used on headers
_custom_static_fields_names=("Application" "Environment")

# CA WILY - apm metric path - to be used with correlated output
_custom_wily_metric_path="Infrastructure|$(hostname -s)|SSL:"

# DX APM - DX apm metric set as:
# agent, metric tree name, metric node
_custom_dxapm_metricset=("Infrastructure" "SSL|Validity")

# AWS CLOUDWATCH - cw namespace
_custom_cw_namespace="SSL Monitoring"

# STATSD - statsd metric name
_custom_statsd_metric_name="ssl.certificate,endpoint"

# GRAPHITE - graphite metric name
_custom_graphite_metric_name="infrastructure.ssl.certificate.days"

# ELASTICSEARCH APM - elasticsearch set as master_label, sample name
_custom_esapm_metricset=("infrastructure" "ssl")

# PROMETHEUS - metricset like - include metadata (true/false), metric name, label name
_custom_prometheus_metricset=("true" "ssl_certificate_validation" "endpoint")

# instrumentation endpoint 
_custom_instrumentation_addr="http://localhost:5001/metricfeed"
# send method / command
_custom_instrumentation_cmd="curl --silent -i -H \"Content-type: application/json\" -XPOST ${_custom_instrumentation_addr} --data-binary"
#
# end custom configs

# hey you! yep, you! unless you know what you're doing... 
# Do not touch Willie. Good advice.
# not beyond this line... things may get serious from now on.

# get the skeletons out of the closet and move on with fun stuff - start from the begging 
# runtime globals / variable initialization
_this="$(basename "${BASH_SOURCE[0]}")"
_this_path="$( cd "$(dirname "${BASH_SOURCE[0]}")" || return 0 ; pwd -P )"
_config_file="${_this_path}/conf/config.${_this//.sh/.env}"
_local_certs_path="${_this_path}/cert_files"
_rm_cmd=$(command -v rm)
_global_OLDIFS="${IFS}"
_noheader="false"
_shootmail="false"
_outputSAN=""
_static_field_exist=0
_alt_label=""
_extrafields_c=0

# default umask to be somewhat restrictive - probably waste of time
umask 077 

function cleanup() {
    # what: cleanup temp files
    # arg: exit code of die - optional, if 8 is given clean any output file
    eval "${_rm_cmd}" -f "${_cert_temp}" 
    eval "${_rm_cmd}" -f "${_error_temp}" 
    eval "${_rm_cmd}" -f "${_output_temp}"
    eval "${_rm_cmd}" -f "${_chain_temp}"
    [[ "${1}" -eq 8 ]] && eval "${_rm_cmd}" -f "${_output_file}"
}

function die() { 
    # what: don't utter a single word - actually do, if needed based on exit code
    # args: exit_code[1] complimentary_message[2] sometimes[3]
    cleanup "${1}"
    case "${1}" in
    # melow
        0) exit "${1}" ;;
    # missing dependency
        3) echo "${2} is just a suggestion, just like pants." && exit "${1}";;
    # 5 malformed command
        5) echo "Me fail English? That's unpossible." && exit "${1}";;
    # interrupted, INT caught
        8) echo && echo "Operator! Give me the number for 911!" && exit "${1}";;
    # file error
        13) echo "Bwow-chicka-bwow I'd RAP about ${2}... If I could ${3} it." && exit "${1}";;
    # fqdn list related errors
        15) echo "I hope I didn’t brain my damage with that ${2} you gave me." && exit "${1}";;
    # anything else, make msg optional
        *) [[ -n "${2}" ]] && echo "${2}" ; exit "${1}" ;;
    esac
}

# if config file exists and is valid, use it
mkdir -p "${_this_path}/conf" 2> /dev/null || die 13 "./conf" "write"
if [[ -x "${_config_file}" ]]; then
    if [[ $(grep -c "^_" "${_config_file}" | bc) -ne 0 ]]; then
        # shellcheck source=${_this_path}/conf/
        # shellcheck disable=SC1091
        source "${_config_file}"
    fi
fi

# basic functions
function manual() {
    # what: show script manual - may have gone too far
    local _BOLD_ && _BOLD_=$(tput bold)
    local _NORM_ && _NORM_=$(tput sgr0)
    echo ""
    echo " ${_BOLD_}${_my_name} v${_my_version}${_NORM_}"
    echo ""
    echo " ${_BOLD_}USAGE${_NORM_}"
    echo "  ${0} [manual|-v] [-n|-x|-m|-i]"
    echo "  { [-s HOST -p PORT] | [-f LOCAL_CERTIFICATE_FILE] [-l FQDN_LIST_FILE] [-u RESOURCE_URL] }"
    echo "  [-t(tty|csv|html|json|cw|wily|dxapm|statsd|prometheus|graphite|esapm)]"
    echo "  [-e(issuer,cn,serial)] [-S] [-E|(c|C)] [-d] [-P]"
    echo "  [-o/-or(column_number)|(columnA_number,columnB_number)] [-F/-F-(pattern)] [-O save_to_file]"
    echo ""
    echo "-----------------------------------------------------------------------------------------------------------------"
    echo " ${_BOLD_}CONFIGURATION${_NORM_}"
    echo ""
    echo "  You can either change values on top of the script or use a ${_BOLD_}${_config_file}${_NORM_}."
    echo "  If config file is found, valid and executable, it will be sourced and any varible set there will have prevalence"
    echo "  over the ones on the script replacing theirs equivalents."
    echo ""
    echo " ${_BOLD_}CONFIGURATION${_NORM_}"
    echo "-----------------------------------------------------------------------------------------------------------------"
    echo " ${_BOLD_}REMOTE HOST${_NORM_}"
    echo "  ${0} -s HOST -p PORT"
    echo ""
    echo " WHERE"
    echo "  ${_BOLD_}-s${_NORM_}    : Hostname/IP address to query certificate of"
    echo "  ${_BOLD_}-p${_NORM_}    : SSL/Secure Port number. If not specified, ${_BOLD_}'443'${_NORM_} is assumed."
    echo ""
    echo " Example:"
    echo "  ${0} -s google.com -p 443"
    echo "  Host            | Status  | Expires     | Days"
    echo "  google.com:443  | Valid   | Aug 2 2021  | 58"
    echo ""
    echo "-----------------------------------------------------------------------------------------------------------------"
    echo " ${_BOLD_}LOCAL FILE${_NORM_}"
    echo "  ${0} -f LOCAL_CERTIFICATE_FILE"
    echo ""
    echo " WHERE"
    echo "  ${_BOLD_}-f${_NORM_}    : Local certificate file path"
    echo ""
    echo " Example:"
    echo "  ${0} -f ~/Certs/Entrust_G2_CA.cer"
    echo "  Host                    | Status  | Expires     | Days"
    echo "  FILE:Entrust_G2_CA.cer  | Valid   | Dec 7 2030  | 3472"
    echo ""
    echo " * PEM, DER and SiteMinder XML Metadata certs are supported"
    echo ""
    echo "-----------------------------------------------------------------------------------------------------------------"
    echo " ${_BOLD_}RESOURCE URL${_NORM_}"
    echo "  ${0} -u RESOURCE_URL"
    echo ""
    echo " WHERE"
    echo "  ${_BOLD_}-u${_NORM_}    : Resource URL to download the cert from"
    echo ""
    echo " Example:"
    echo "  ${0} -u http://mysite.com/download/certfile.cer"
    echo "  Host                        | Status    | Expires       | Days"
    echo "  URL:mysite.com/certfile.cer | Valid     | Jun 20 2031   | 3650"
    echo ""
    echo " * PEM, DER and SiteMinder XML Metadata certs are supported"
    echo ""
    echo "-----------------------------------------------------------------------------------------------------------------"
    echo " ${_BOLD_}LIST${_NORM_}"
    echo "  ${0} -l FQDN_LIST_FILE [-o(n)|-F(-)]"
    echo ""
    echo "  ${_BOLD_}Execution may look hang when running with a bigger list file, it's not. This is just like bankruptcy law...${_NORM_}"
    echo "  ${_BOLD_}Don't worry about it. I got this...${_NORM_}"
    echo ""
    echo " WHERE"
    echo "  ${_BOLD_}-l${_NORM_}    : List file containing certs to go thru, fields must be split by spaces as:"
    echo "  HOST PORT"
    echo ""
    echo " Example:"
    echo "  google.com 443"
    echo "  github.com 443"
    echo ""
    echo "  ${_BOLD_}*${_NORM_} You can include local files on list using ${_BOLD_}'FILE'${_NORM_} keyword, as:"
    echo "  CERT_FILE_PATH FILE"
    echo ""
    echo " Example:"
    echo "  /home/user/certs/cert1.pem FILE"
    echo "  /home/user/certs/cert2.pem FILE"
    echo ""
    echo " Considering below list file, for example:"
    echo "  google.com 443"
    echo "  /home/user/certs/Entrust_G2_CA.cer FILE"
    echo ""
    echo " Results will be:"
    echo "  ${0} -l list"
    echo "  Host                   | Status  | Expires      | Days"
    echo "  google.com:443         | Valid   | Aug 2 2021   | 58"
    echo "  FILE:Entrust_G2_CA.cer | Valid   | Dec 7 2030   | 3472"
    echo ""
    echo "${_BOLD_}**${_NORM_} You can do exactly the same with ${_BOLD_}'URL'${_NORM_} keyword."
    echo ""
    echo " When running against a list, you can opt for an alternative label to be shown instead of default"
    echo " output (host:port, file:FILE, url:URL), just put the label you want before HOST/FILE/URL and split"
    echo " them with a ';' (semicolon), like:"
    echo "  GOOGLE;google.com 443"
    echo ""
    echo " Results will be shown as:"
    echo "  ${0} -l list"
    echo "  Host             | Status       | Expires      | Days"
    echo "  GOOGLE           | Valid        | Sep 14 2021  | 67"
    echo ""
    echo "${_BOLD_}**${_NORM_} Note that all info about the endpoint (host/file/url/port) is ommited when alternative label is used."
    echo ""
    echo " If you running thru a list and generating a html output (exclusively), you can use a ${_BOLD_}separator${_NORM_} to well..."
    echo " separate things. Like:"
    echo "  _separator;Google Sites"
    echo "  google.com 443"
    echo "  gmail.com 443"
    echo "  _separator;Local Files"
    echo "  /home/user/certs/Entrust_G2_CA.cer FILE"
    echo ""
    echo " _separator must be written as ${_BOLD_}_separator;HEADER_NAME${_NORM_}, example:"
    echo "  _separator;EXTERNAL SITES"
    echo ""
    echo "${_BOLD_}**${_NORM_} ignored if output type is not html"
    echo "${_BOLD_}**${_NORM_} ignored if ordering or filtering results"
    echo "${_BOLD_}**${_NORM_} ignored if header is omitted"
    echo ""
    echo ""
    echo " ${_BOLD_}*${_NORM_} You can also use static fields on the list file - your own identifiers for example, whatever you need."
    echo " This is specially useful when you require some 'shape' on a bigger list."
    echo "  ${_BOLD_}**${_NORM_} Static fields are limited to the max of three(3) fields - output starts to get ugly."
    echo ""
    echo " In order to use static fields, you need to define custom variables, as follow:"
    echo "  ${_BOLD_}_custom_static_fields_pos${_NORM_}     : Where to position the fields on the results as ${_BOLD_}'begin'${_NORM_} or ${_BOLD_}'end'${_NORM_}"
    echo "  ${_BOLD_}_custom_static_fields_names${_NORM_}   : Array containing static fields names to be used on header."
    echo ""
    echo " Finally, to have static fields working properly you need to put them on the ${_BOLD_}begging${_NORM_} of the line as:"
    echo " ${_BOLD_}STATIC_FIELD_1 STATIC_FIELD_2 STATIC_FIELD_3 HOST|PATH PORT|<FILE>${_NORM_}"
    echo ""
    echo " Example:"
    echo " MainApp Production JackOfAllTrades google.com 443"
    echo ""
    echo " Wrapping it all... Let's take below list with static fields for instance:"
    echo "  App1 Eric_Schmidt Mountain_View google.com 443"
    echo "  App2 Chris_Wanstrath San_Francisco github.com 443"
    echo ""
    echo " Note that static fields and its headers names can ${_BOLD_}NOT${_NORM_} have spaces on it. The best you can use is '_' (underline)."
    echo " The less of evils... Going further and considering above list file, and as stated before, assuming you'd set custom static"
    echo " field variables, position and header names, example:"
    echo "  ${_BOLD_}_custom_static_fields_pos=${_NORM_}\"begin\""
    echo "  ${_BOLD_}_custom_static_fields_names=${_NORM_}(\"Id\" \"Chairman\" \"Headquarters\")"
    echo ""
    echo " Finally, using this list:"
    echo "  ${0} -l list"
    echo "  Id    | Chairman        | Headquarters    | Host            | Status  | Expires      | Days"
    echo "  App1  | Eric_Schmidt    | Mountain_View   | google.com:443  | Valid   | Aug 2 2021   | 58"
    echo "  App2  | Chris_Wanstrath | San_Francisco   | github.com:443  | Valid   | Mar 30 2022  | 298"
    echo ""
    echo " ${_BOLD_}Woo-hoo! Four day weekend, hun?!${_NORM_}"
    echo ""
    echo ""
    echo "  ${_BOLD_}-o${_NORM_}    : Sort/order output by column number (nth); reverse order with 'r', example:"
    echo "  ${_BOLD_}-o2${_NORM_}   : Sort results by column number 2"
    echo "  ${_BOLD_}-or2${_NORM_}  : Sort results in reverse order by column number 2"
    echo ""
    echo "  You can also order by two columns, like - order by column A then by column B, example:"
    echo "  ${_BOLD_}-o1,4${_NORM_} : Sort by column number 2, then by column number 4"
    echo "  ${_BOLD_}-or1,4${_NORM_} : Sort results in reverse order column number 2, then by column number 4"
    echo ""
    echo "  ${_BOLD_}**${_NORM_} Ignored depending on the output type"
    echo "  ${_BOLD_}**${_NORM_} Ignored if specified column number is out of bounds, example: used '6' on a run that yields a '5' columns output."
    echo ""
    echo "  ${_BOLD_}-F${_NORM_}                : Filter output by pattern, whenever it exists - void with '-', applies to any column/value, example:"
    echo "  ${_BOLD_}-FValid${_NORM_}           : Show only lines that contains 'Valid'"
    echo "  ${_BOLD_}-F-Unreachable${_NORM_}    : Do not show lines containing 'Unreachable'"
    echo "  ${_BOLD_}-F-site1.com${_NORM_}      : Do not show lines containing 'site1.com'"
    echo ""
    echo "-----------------------------------------------------------------------------------------------------------------"
    echo " ${_BOLD_}FORMATTING OPTIONS${_NORM_}"
    echo ""
    echo " ${_BOLD_}-t${_NORM_}     : Output type. If not specified, ${_BOLD_}'tty'${_NORM_} is assumed."
    echo " Accepted values are:"
    echo ""
    echo "  ${_BOLD_}- tty${_NORM_}         : Pretty console ${_BOLD_}*${_NORM_}default"
    echo "  ${_BOLD_}- csv${_NORM_}         : Delimiters gonna rule and delimit"
    echo "  ${_BOLD_}- html${_NORM_}        : Eich tee eme ell. Lynx? Netscape?"
    echo "  ${_BOLD_}- json${_NORM_}        : Get your gollie mask on! RFC 8559 compliant JSON"
    echo "  ${_BOLD_}- cw${_NORM_}          : AWS CloudWatch PutMetric"
    echo "      ${_BOLD_}*${_NORM_}custom var ${_BOLD_}_custom_cw_namespace${_NORM_} must be set"
    echo "  ${_BOLD_}- wily${_NORM_}        : CA Wily Introscope metric"
    echo "      ${_BOLD_}*${_NORM_}custom var ${_BOLD_}_custom_wily_metric_path${_NORM_} must be set"
    echo "  ${_BOLD_}- dxapm${_NORM_}       : Broadcom DX APM metric"
    echo "      ${_BOLD_}*${_NORM_}custom var ${_BOLD_}_custom_dxapm_metricset${_NORM_} must be set"
    echo "  ${_BOLD_}- statsd${_NORM_}      : Statds metric, suitable for DataDog and Influx"
    echo "      ${_BOLD_}*${_NORM_}custom var ${_BOLD_}_custom_statsd_metric_name${_NORM_} must be set"
    echo "  ${_BOLD_}- prometheus${_NORM_}  : Prometheus metric"
    echo "      ${_BOLD_}*${_NORM_}custom var ${_BOLD_}_custom_prometheus_metricset${_NORM_} must be set"
    echo "  ${_BOLD_}- graphite${_NORM_}    : Graphite metric"
    echo "      ${_BOLD_}*${_NORM_}custom var ${_BOLD_}_custom_graphite_metric_name${_NORM_} must be set"
    echo "  ${_BOLD_}- esapm${_NORM_}       : ElasticSearch APM metric"
    echo "      ${_BOLD_}*${_NORM_}custom var ${_BOLD_}_custom_esapm_metricset${_NORM_} must be set"
    echo ""
    echo " ${_BOLD_}-e${_NORM_}     : Show extra info from certificate."
    echo " Accepted values are:"
    echo ""
    echo "  ${_BOLD_}- cn${_NORM_}      : Certificate common name"
    echo "  ${_BOLD_}- issuer${_NORM_}  : Certificate issuer"
    echo "  ${_BOLD_}- serial${_NORM_}  : Certificate serial"
    echo ""
    echo "  Use one argument or any combination of them, separated by commas, like:"
    echo "  ${0} -s google.com ${_BOLD_}-ecn${_NORM_}"
    echo "  ${0} -s google.com ${_BOLD_}-ecn,serial${_NORM_}"
    echo "  ${0} -s google.com ${_BOLD_}-ecn,serial,issuer${_NORM_}"
    echo ""
    echo " ${_BOLD_}-S${_NORM_}     : Show certificate SANs, if any (output may get VERY ugly)"
    echo ""
    echo " ${_BOLD_}-n${_NORM_}     : Do not show header"
    echo "  ${_BOLD_}**${_NORM_} Ignored depending on the output type"
    echo ""
    echo "-----------------------------------------------------------------------------------------------------------------"
    echo " ${_BOLD_}MISC${_NORM_}"
    echo ""
    echo " ${_BOLD_}-m${_NORM_}     : Send results by email"
    echo "  ${_BOLD_}**${_NORM_} custom variables must be set, as follow:"
    echo "  ${_BOLD_}_custom_mail_to${_NORM_}       : recipient's email/s. split multiple emails with commas, as: mail1,mail2"
    echo "  ${_BOLD_}_custom_mail_from${_NORM_}     : sender's email"
    echo "  ${_BOLD_}_custom_mail_subject${_NORM_}  : email subject"
    echo ""
    echo "  ${_BOLD_}**${_NORM_} email goes out thru either sendmail (default) or telnet (funky); in case you want to use telnet"
    echo "  you must set an additional custom variable:"
    echo "  ${_BOLD_}_custom_mail_usealtmechanism${_NORM_}      : an array worth of ('true' 'domain.com' 'mailhost_addr' 'mailhost_port'"
    echo ""
    echo " ${_BOLD_}-O${_NORM_}     : Save results to file ${_BOLD_}*${_NORM_}defaults to stdout"
    echo ""
    echo " ${_BOLD_}-E${_NORM_}     : Export certificate to ${_BOLD_}PWD/cert_files${_NORM_}"
    echo " ${_BOLD_}-Ec${_NORM_}    : Export server certificate chain to ${_BOLD_}PWD/cert_files${_NORM_} on a single file."
    echo " ${_BOLD_}-Ec${_NORM_}    : Export server certificate chain to ${_BOLD_}PWD/cert_files${_NORM_} on separated files."
    echo "  ${_BOLD_}**${_NORM_} only valid when running against server or URL"
    echo "  ${_BOLD_}**${_NORM_} chain export is only available when running against server"
    echo ""
    echo " ${_BOLD_}-d${_NORM_}     : Dump certificate 'interesting' info without much data handling"
    echo "  ${_BOLD_}**${_NORM_} only valid when running against a single FILE"
    echo ""
    echo " ${_BOLD_}-P${_NORM_}     : Show progress bar when running over a list"
    echo ""
    echo " ${_BOLD_}-i${_NORM_}     : Inject results to instrumentation endpoint"
    echo "  ${_BOLD_}**${_NORM_} custom variables must be set, as follow:"
    echo "  ${_BOLD_}_custom_instrumentation_addr${_NORM_}      : instrumentation endpoint server/URL"
    echo "  ${_BOLD_}_custom_instrumentation_cmd${_NORM_}       : command to be used for metric injection" 
    echo ""
    echo " ${_BOLD_}-x${_NORM_}     : Debug execution. Ye ol' and ugly friend ${_BOLD_}'set -x'${_NORM_}"
    echo "  ${_BOLD_}**${_NORM_} all temporary files are left behind when '-x' is used, they can be useful."
    echo ""
    echo " ${_BOLD_}-v${_NORM_}     : Version information"
    echo ""
    echo " ${_BOLD_}**${_NORM_}Some options and/or arguments are mutually exclusive and will either fail or be ignored."
    echo ""
    echo "-----------------------------------------------------------------------------------------------------------------"
    echo " ${_BOLD_}STAMIN FOR UNREACHABLE ENDPOINTS${_NORM_}"
    echo ""
    echo "  There is a 'pseudo retry' function for whenever an endpoint is found unrechable, it can search for the correlated local"
    echo "  certificate on the ${BOLD}_local_certs_path${NORM} - controlable by the variable ${BOLD}_seek_local_certs${NORM} - which"
    echo "  should be true or false. Important to mention that said files should follow a specific naming pattern to be 'seen', that's"
    echo "  the same naming convention used when exporting a certificate, like for example:"
    echo ""
    echo "      ${BOLD}SERVER${NORM}"
    echo "      server name and port        : ${BOLD}google.com 443${NORM}"
    echo "      local file should be named  : ${BOLD}google.com_443.cer${NORM}"
    echo ""
    echo "      ${BOLD}URL${NORM}"
    echo "      URL                         : ${BOLD}https://google.com/files/certificates/file${NORM}"
    echo "      local file should be named  : ${BOLD}google.com_files_certificates_file.cert${NORM}"
    echo ""
    echo "  If that happens, endpoint unreachable AND _seek_local_certs is 'true' AND correlated file found on _local_certs_path, a"
    echo "  notation as 'local' will be placed on the line to indicate date was pull from a local file, example:"
    echo ""
    echo "  ${0} -s google.com"
    echo "  Host                    | Status  | Expires     | Days"
    echo "  google.com:443 (local)  | Valid   | Oct 4 2021  | 50"
    echo ""
    echo "-----------------------------------------------------------------------------------------------------------------"
    echo " ${_BOLD_}CUSTOM CONFIGS${_NORM_}"
    echo ""
    echo "  Listing all of them et their meaning..."
    echo ""
    echo "  ${BOLD}Common${NORM}"
    echo "  ${BOLD}* _warning_notice${NORM}     : how many days should be considered warning? anything less than this "
    echo "      set will be seen as a warning; set to 30 by default."
    echo "  ${BOLD}* _openssl_proxy${NORM}      : HTTP proxy to be used with OpenSSL \* when available to OpenSSL (v2.0+)"
    echo "      ${_BOLD_}**${_NORM_}setting _openssl_proxy will make all calls run over the proxy"
    echo "      ${_BOLD_}**${_NORM_}if empty, will use ENV ALL_PROXY if available; and finally ignore if it's not set"
    echo "      ${_BOLD_}**${_NORM_}when proxy is set, discovery is skipped and all hosts are treated as live"
    echo "  ${BOLD}* _seek_local_certs${NORM}   : whether to seek or not for local certs when endpoint is unreacheable - read"
    echo "      section ${BOLD}Stamin for unreachable endpoints${NORM} for more info - should be true or false"
    echo "  ${BOLD}* _local_certs_path${NORM}   : where to seek for local files"
    echo ""
    echo "  ${BOLD}Email Variables${NORM}"
    echo "  ${BOLD}* _custom_mail_usealtmechanism${NORM}    : use alternative email mechanism thru telnet? if not set,"
    echo "      sendmail will be used. to be considered, this var should be set as:"
    echo "      true|false, domain, mailhost_addr, mailhost_port"
    echo "      obviously only considered if first element is set to 'true'"
    echo "  ${BOLD}* _custom_mail_to${NORM}                 : recipient's email/s. split addr with commas, as: addr1,addr2."
    echo "  ${BOLD}* _custom_mail_from${NORM}               : sender's email"
    echo "  ${BOLD}* _custom_mail_from_name${NORM}          : sender's name - if you want to show off"
    echo "  ${BOLD}* _custom_mail_from_return_path${NORM}   : set a different return path and reply-to?"
    echo "  ${BOLD}* _custom_mail_subject                   : email subject"
    echo "  ${BOLD}* _custom_mail_signature                 : email signature, if you want it - must use HTML escaped code, ex:"
    echo '      _custom_mail_signature="<p><span style=\"signature\">A Rocksome SSL Monitoring Tool</span></p>"'
    echo "  ${BOLD}* custom_html_style${NORM}               : custom email stylesheet for HTML emails - must use HTML escaped code"
    echo ""
    echo "  ${BOLD}Output Specic Variables${NORM}"
    echo "  ${BOLD}* _custom_static_fields_pos${NORM}       : where to position static fields 'begin' OR 'end' of the line"
    echo "  ${BOLD}* _custom_static_fields_names${NORM}     : static fields names to be used on headers"
    echo "  ${BOLD}* _custom_wily_metric_path${NORM}        : CA WILY - apm metric path - to be used with correlated output"
    echo "  ${BOLD}* _custom_dxapm_metricset${NORM}         : DX APM - DX apm metric set as: agent, metric tree name, metric node"
    echo "  ${BOLD}* _custom_cw_namespace${NORM}            : AWS CLOUDWATCH - cw namespace"
    echo "  ${BOLD}* _custom_statsd_metric_name${NORM}      : STATSD - statsd metric name"
    echo "  ${BOLD}* _custom_graphite_metric_name${NORM}    : GRAPHITE - graphite metric name"
    echo "  ${BOLD}* _custom_esapm_metricset${NORM}         : ELASTICSEARCH APM - elasticsearch set as: master_label, sample name"
    echo "  ${BOLD}* _custom_prometheus_metricset${NORM}    : PROMETHEUS - metricset like - include metadata (true/false), metric name, label name"
    echo ""
    echo "  ${BOLD}Instrumentation Endpoint${NORM}"
    echo "  ${BOLD}* _custom_instrumentation_addr${NORM}    : instrumentation endpoint URL"
    echo "  ${BOLD}* _custom_instrumentation_cmd${NORM}     : send method and command"
    echo ""
    echo "-----------------------------------------------------------------------------------------------------------------"
    echo " ${_BOLD_}EXIT CODES${_NORM_}"
    echo ""
    echo "  0   :   mellow, clean/normal exit"
    echo "  3   :   missing dependency/var not set"
    echo "  5   :   malformed command"
    echo "  8   :   interrupted, INT caught"
    echo "  13  :   input/output/file error"
    echo "  15  :   FQDN file list related error"
    echo ""
    echo "-----------------------------------------------------------------------------------------------------------------"
    echo ""
}

function quickhelp() {
    # what: usage may be too big for showing at every user's mistake - happens a lot - so shows a quickie instead
    echo ""
    echo "${_my_name} v${_my_version}"
    echo ""
    echo " USAGE"
    echo "      ${0} [manual|-v] [-n|-x|-m|-i]"
    echo "      { [-s HOST -p PORT] | [-f LOCAL_CERTIFICATE_FILE] [-l FQDN_LIST_FILE] [-u RESOURCE_URL] }"
    echo "      [-t(tty|csv|html|json|cw|wily|dxapm|statsd|prometheus|graphite|esapm)]"
    echo "      [-e(issuer,cn,serial)] [-S] [-E|(c|C)] [-d] [-P]"
    echo "      [-o/-or(column_number)|(columnA_number,columnB_number)] [-F/-F-(pattern)] [-O save_to_file]"
    echo ""
    echo " FOR MORE INFO"
    echo "      ${0} manual"
    echo ""
}

# check if all good with bash
[[ -z "${BASH}" || "${BASH_VERSINFO[0]}" -lt 3 ]] && die 3 "bash 3+"

# if interruption is caught, clean-up and exit
trap 'die "8"' INT

function zitheer() {
    # what: check if dependency is satisfied
    # args: command[1]
    local _cmd && _cmd=$(command -v "${1}")
    [[ -n "${_cmd}" ]] && [[ -f "${_cmd}" ]]
    return "${?}" 
}

# test it already for main deps - specific other ones might appear later
for _dep in "${_deps[@]}"; do zitheer "${_dep}" || die 3 "${_dep}"; done

# if running on MacOS we need perl to emulate timeout
if [[ $(uname -s) == "Darwin" ]]; then 
    if ! zitheer perl; then
        die 3 "perl"
    else
        # conditional function declaration in case running on Darwin and timeout not available
        function _timeout() { 
        # what: emulate timeout on MacOS or Unix. depends on perl thou, no free lunch man!
        # args: seconds_2_die[1]
        ( trap 'exit 1' SIGALRM;
        perl -e 'alarm shift; exec @ARGV;' "$@" ) > /dev/null 2>&1 || return 1
        }
    fi
elif [[ $(command -v timeout) ]]; then
    unset -f _timeout
else
    die 3 "timeout"
fi

function groundset() {
    # what: set some base to go further
    # when TLS is present, make use of openssl servername arg when available
    if openssl s_client -help 2>&1 | grep "\-servername" > /dev/null; then
        _tls_server_name="true"
    else
        _tls_server_name="false"
    fi

    # test whether proxy arg is available to openssl
    if openssl s_client -help 2>&1 | grep "\-proxy" > /dev/null; then
        if [[ -z "${_openssl_proxy}" ]] && [[ -n "${ALL_PROXY}" ]]; then
            _openssl_proxy="${ALL_PROXY}"
        fi
    else
        unset _openssl_proxy
    fi

    # define temp files and touch it
    _cert_temp=$(mktemp /tmp/"${_this//.sh/}"_cert_temp.XXXXXX 2> /dev/null) || die 13 "_cert_temp" "write"
    _error_temp=$(mktemp /tmp/"${_this//.sh/}"_error_temp.XXXXXX 2> /dev/null) || die 13 "_error_temp" "write"
    _output_temp=$(mktemp /tmp/"${_this//.sh/}"_output_temp.XXXXXX 2> /dev/null) || die 13 "_output_temp" "write"
    touch "${_cert_temp}" "${_error_temp}" "${_output_temp}" 2> /dev/null || die 13 "temp files" "write"

    # hook into today's date for comparisons
    _global_month=$(date "+%m")
    _global_day=$(date "+%d")
    _global_year=$(date "+%Y")
    _now_julian=$(gimmejulian "${_global_month#0}" "${_global_day#0}" "${_global_year}")
}

function whatsmaprogress {
    # what: show progress for when running thru a list
    # args: start[1] end[2]
    # process data
    ! [[ "${_showprogress}" == "true" ]] && return 0
    _progress=$((${1}*100*100/${2})) && _progress=$((_progress/100))
    _done=$((_progress*4)) && _done=$((_done/10))
    _left=$((40-_done))
    # build the lenghts 
    _fill=$(printf "%${_done}s")
    _empty=$(printf "%${_left}s")
    # build bar strings and print the line
    if [[ "${_progress}" -ne 100 ]]; then
        printf "\rProgress : [${_fill// /#}${_empty// /-}] ${_progress}%%"
    else
        printf "\rProgress : [${_fill// /#}${_empty// /-}] ${_progress}%%\n"
    fi
}

# date functions - a lot of ping/pong to get a value
function datediff() {
    # what: calc seconds between two dates
    # args: date1[1] date2[2]
    local _date1="${1}"
    local _date2="${2}"
    echo $((_date2 - _date1))
}

function gimmejulian() {
    # what: convert a date from MM-DD-YYYY to julian format
    # args: month[1] day[2] year[3]
    local _month _day _year _jmonth_temp _jyear_temp 
    _month="${1}" _day="${2}" _year="${3}"

    # since leap years make Feb with 29days, calcs are made 
    # using a fictional date - 1/March/0000 -  as ref point
    _jmonth_temp=$((12 * _year + _month - 3))

    # if we're not in March yet, year is changed to the previous one
    _jyear_temp=$((_jmonth_temp / 12))

    # the number of days from 1/March/0000 is now calculated
    # and number of days from 1/Jan/4713BC is added
    _res=$(( (734 * _jmonth_temp + 15) / 24
        - 2 * _jyear_temp + _jyear_temp/4
        - _jyear_temp/100 + _jyear_temp/400 + _day + 1721119 ))
    echo "${_res}"
}

function gimmemonth() {
    # what: convert month string to integer
    # args: abreviated_month_name[1]
    local _monthstring="${1}"
    case "${_monthstring}" in
        Jan) echo 1 ;;
        Feb) echo 2 ;;
        Mar) echo 3 ;;
        Apr) echo 4 ;;
        May) echo 5 ;;
        Jun) echo 6 ;;
        Jul) echo 7 ;;
        Aug) echo 8 ;;
        Sep) echo 9 ;;
        Oct) echo 10 ;;
        Nov) echo 11 ;;
        Dec) echo 12 ;;
          *) echo 0 ;;
    esac
}

function fqdnshape() {
    # what: validate FQDN list file
    # assumes 1st line is well formed, then then check if other lines have same number of columns as it

    # check if whole file has the same ammount of columns
    if ! grep -Ev "(^#|^$|^_separator)" "${_fqdn_file}" | awk -F ' ' 'NR==1{NCOLS=NF};NF!=NCOLS{exit 1}' > /dev/null; then
        return 1
    fi
    # if above passed, check how many columns the file has
    _fqdn_col_c=$(grep -Ev "(^#|^$|^_separator)" "${_fqdn_file}" | head -1 | awk -F ' ' '{print NF}' | bc)

    # check if there are no EOL spaces
    [[ $(grep -Ev "(^#|^$|^_separator)" "${_fqdn_file}" | grep -Ec " $" | bc) -ne 0 ]] && die 15 "${_fqdn_file}"

    # fqdnfile has to have at least 2 cols and no more than 5
    if [[ "${_fqdn_col_c}" -lt 2 || "${_fqdn_col_c}" -gt 5 ]]; then
        die 15 "${_fqdn_file}"
    # default 2 cols, return nothing but 0
    elif [[ "${_fqdn_col_c}" -eq 2 ]]; then
        return 0
    # if _fqdn_col_c is higher than 2 it means static fiedls are being used, validate the correlated var
    elif [[ "${_fqdn_col_c}" -gt 2 ]]; then
        if [[ -z "${_custom_static_fields_pos}" || "${#_custom_static_fields_names[@]}" -eq 0 ]]; then
            die 3 "static fields variable"
        else
            # get how many static fields exists and if we have the same ammount on header names array
            if [[ "${#_custom_static_fields_names[@]}" -ne $(( _fqdn_col_c - 2 )) ]]; then
                die 15 "header variable"
            else
                _static_field_exist=1
            fi
        fi
    fi
}

function htmlshape() {
    # what: just define html base style
    # this can be defined as custom on config file thru _custom_html_style - if that's the case, value from config file will be used
    [[ -n "${_custom_html_style}" ]] && _html_style="${_custom_html_style}" && return 0
    _html_style="<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">
<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\" lang=\"en\">
<head>
<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"/>
<style type=\"text/css\">
        body {
            margin: 1 0 0 2;
            padding: 0;
        }
        font {
            font:normal 12px verdana, arial, helvetica, sans-serif;
        }
        .bold {
            font:bold 12px verdana, arial, helvetica, sans-serif;
            color:#2E2E2E;
        }
        .notbold {
            font:normal 12px verdana, arial, helvetica, sans-serif;
            color:#2E2E2E;
        }
        table {
            background:#f9f9f9;
            border:1px solid black;
            border-collapse:collapse;
            font:normal 12px verdana, arial, helvetica, sans-serif;
            width:80%;
        }
        td {
            padding:.4em;
            text-align:left;
            border:1px solid black;
            width:max-content;
        }
        td.health {
            /* color:#2E2E2E; */
            /* background:green; */
            color:green;
        }
        th {
            /* color:#2E2E2E; */
            color:#E20074;
            background:#d5d8dc;
            text-align:center;
            border:1px solid black;
            text-transform:uppercase;
            font:bold 12px verdana, arial, helvetica, sans-serif;
            width:max-content;
        }
        th.separator {
            color:#2E2E2E;
        }
        tr {
            color:#2E2E2E;
            border:1px solid black;
        }
        tr.warning{
            color:#2E2E2E;
            background:yellow;
        }
        tr.critical{
            color:#F2F2F2;
            background:red;
        }
</style><title>${_my_name}</title></head>
<body><p><br/></p>"
}

function mailshape() {
    # what: just define email headers
    # check if multiple rcpt and make-up the variable
    _mail_headers="From: ${_custom_mail_from_name} <${_custom_mail_from}>
Subject: ${_custom_mail_subject}
Thread-Topic: ${_custom_mail_subject}
To: ${_custom_mail_to//,/, }
CC: 
Reply-To: ${_custom_mail_from_return_path}
Return-Path: ${_custom_mail_from_return_path}
Accept-Language: en-US
Content-Language: en-US
user-agent: EHLOWendy
X-WockaInfo: SSLPoochWoofWoofAT$(hostname)
MIME-Version: 1.0
Transport-Options: /return
Importance: Normal
Content-Type: multipart/mixed; boundary=\"b0b4f3ttr0ck5/sslpooch\"
This is a MIME-encapsulated message
--b0b4f3ttr0ck5/sslpooch
Content-Type: text/html; charset=\"UTF-8\"
Content-Disposition: inline

"
}

function shout2mail() {
    # what: email results
    local _mail_body
    # build mail headers and body
    _mail_body=$(cat "${_output_file}")
    # always send email as HTML, however preserve preformattted text if HTML format is not specified
    htmlshape
    mailshape
    if [[ "${_outputtype}" != "html" ]]; then
        _mail_body="${_mail_headers}${_html_style}<pre><code>${_mail_body}</code></pre></body></html>"
    else
        _mail_body="${_mail_headers}${_mail_body}"
    fi
    echo "${_mail_body}" > "${_output_file}"
    sleep 1s
    if [[ "${_custom_mail_usealtmechanism[0]}" != "true" ]]; then
        sendmail -t < "${_output_file}"
    else
        [[ "${#_custom_mail_usealtmechanism[@]}" -ne 4 ]] && die 3 "email variable"
        # send mail thru telnet instead
        # check if multiple addr are used, if so build a loop out of it
        if [[ $(echo "${_custom_mail_to}" | grep -c ',' | bc 2>/dev/null) -ne 0 ]]; then
            _custom_mail_to="${_custom_mail_to//,/ }"
            local _loop_rcpt="true"
        fi
        # cant use the same loop as it's using a subshell
        if [[ "${_loop_rcpt}" == "true" ]]; then
            { sleep 2; echo "ehlo ${_custom_mail_usealtmechanism[1]}"; sleep 2;
            echo "mail from: <${_custom_mail_from}>"; sleep 2; 
                for _i in $_custom_mail_to; do
                    echo "rcpt to: <${_i}>"; sleep 2;
                done
            echo "data"; sleep 2; 
            cat "${_output_file}" && echo; sleep 2
            echo "."; sleep 2;
            echo "QUIT"; sleep 1; } | telnet "${_custom_mail_usealtmechanism[2]}" "${_custom_mail_usealtmechanism[3]}" 2> /dev/null 1> /dev/null
        else
            { sleep 2; echo "ehlo ${_custom_mail_usealtmechanism[1]}"; sleep 2;
            echo "mail from: <${_custom_mail_from}>"; sleep 2;
            echo "rcpt to: <${_custom_mail_to}>"; sleep 2;
            echo "data"; sleep 2; 
            cat "${_output_file}" && echo; sleep 2
            echo "."; sleep 2; 
            echo "QUIT"; sleep 1; } | telnet "${_custom_mail_usealtmechanism[2]}" "${_custom_mail_usealtmechanism[3]}" 2> /dev/null 1> /dev/null
        fi
    fi
}

function shout2instrument() {
    # what: inject results to instrumentation endpoint
    if [[ "${_custom_instrumentation_addr}" == "" || "${_custom_instrumentation_cmd}" == "" ]]; then
        die 3 "instrumentation variable" 
    fi

    if [[ $(LC_ALL=C type -t _timeout) == "function" ]]; then
        local _eval_cmd=("_timeout 30" "${_custom_instrumentation_cmd}" "@${_output_file}")
    else
        local _eval_cmd=("timeout -s SIGINT 30s" "${_custom_instrumentation_cmd}" "@${_output_file}")
    fi
    if ! eval "${_eval_cmd[*]}" > /dev/null; then
        die 1 "Life is one crushing defeat after another until you just wish ${_custom_instrumentation_addr} was alive."
    fi
}

# formatting functions
function shout2console() {
    # what: make text output from results. default.
    if [[ -z "${_output_file}" ]]; then
        sed "s/\;/\;\| /g" "${_output_temp}" | column -t -s';'
    else
        sed "s/\;/\;\| /g" "${_output_temp}" | column -t -s';' > "${_output_file}"
    fi
}

function shout2csv() {
    # what: ol' ugly CSV output. results file already comes as this. not much to do.
    if [[ -z "${_output_file}" ]]; then
        cat "${_output_temp}"
    else
        cat "${_output_temp}" > "${_output_file}"
    fi
}

function shout2json() {
    # what: worst function ever. json output.
    local _json_fields && _json_fields=$(head -1 "${_output_temp}")
    local _json_base="{ "
    local _json_ocount && _json_ocount=$(echo "${_json_fields//;/ }" | wc -w | bc)
    local _json_fcount=0

    # define base for fields - they can vary
    for i in ${_json_fields//;/ }; do
        [[ "${_json_ocount}" -ne 1 ]] && _json_base="${_json_base}\"${i}\" : \"_FIELD_${_json_fcount}\","
        [[ "${_json_ocount}" -eq 1 ]] && _json_base="${_json_base}\"${i}\" : \"_FIELD_${_json_fcount}\" }"
        ((_json_ocount--))
        ((_json_fcount++))
    done

    # create an array out of all lines in result file
    IFS=$'\n' read -d '' -r -a LINE < <(tail -n +2 "${_output_temp}")

    # get a pointer so we know when we're in the last element of array
    _json_ocount="${#LINE[@]}" && _json_ocount=$((_json_ocount - 1))

    for i in "${LINE[@]}"; do
        _json_object="${_json_base}"
        IFS=';' read -d '' -r -a LINE_ < <(echo "${i}")
        for ((j=0;j<${#LINE_[@]};j++)); do
            _clean_data=$(echo "${LINE_[$j]}" | tr -d '$')
            _json_object="${_json_object//_FIELD_${j}/${_clean_data}}"
        done
        [[ "${_json_ocount}" -ne 0 ]] && _json_object="${_json_object},"
        ((_json_ocount--))
        _json_file="${_json_file}${_json_object}"
    done
    _json_file="[   ${_json_file}   ]"

    # output the JSON object
    if [[ -z "${_output_file}" ]]; then
        echo "${_json_file}"
    else
        echo "${_json_file}" > "${_output_file}"
    fi
    IFS="${_global_OLDIFS}"
}

function shout2html() {
    # what: make a html from the csv. not much useful unless you're emailing it
    local _html_row
    htmlshape
    _html_file="${_html_style}
<table>"
    _table_header="true"
    while read -r INPUT; do 
        if "${_table_header}"; then
            _html_file="${_html_file}
<tr>
    <th>${INPUT//;/</th><th>}</th>
</tr>
" 
            _table_header="false"
            continue
        fi
    _html_row=""
    # is this line a separator?
    if [[ "${INPUT:0:10}" == "_separator" ]]; then
        # this is messy - separator comes as _separator;colspan;header
        # what kind of separator?
        _html_row="<tr>
    <th class=\"separator\" colspan=\"$(echo "${INPUT}" | cut -d';' -f2)\" style=\"text-align:center;\">$(echo "${INPUT}" | cut -d';' -f3)</th>
</tr>
"
        _html_file="${_html_file}${_html_row}"
        continue
    fi
    if echo "${INPUT}" | grep "Valid" > /dev/null; then
        _html_row=$(echo "<tr>
    <td>${INPUT//;/</td><td>}</td>
</tr>"  | sed "s/<td>Valid/<td class=\"health\">Valid/g")
    elif echo "${INPUT}" | grep "Expiring" > /dev/null; then
        _html_row=$(echo "<tr>
    <td>${INPUT//;/</td><td>}</td>
</tr>" | sed "s/<tr>/<tr class=\"warning\">/g")
    else
        _html_row=$(echo "<tr>
    <td>${INPUT//;/</td><td>}</td>
</tr>" | sed "s/<tr>/<tr class=\"critical\">/g")
    fi 
    _html_file="${_html_file}${_html_row}"
    done < "${_output_temp}"
    _html_file="${_html_file}
</table>
<p></p>
${_custom_mail_signature}
</body>
</html>"

    # output the HTML 
    if [[ -z "${_output_file}" ]]; then
        echo "${_html_file}"
    else
        echo "${_html_file}" > "${_output_file}"
    fi
}

function gimmespace() {
    # what: insert separator on the output file, only valid for html output
    # args: separator_header[0]
    # bail if not html output
    [[ "${_outputtype}" != "html" ]] && return 0
    # bail if no header is used - what's the point? and I cant count the columns though :)
    [[ "${_noheader}" == "true" ]] && return 0
    # bail if order or filter were used
    [[ -n "${_orderby}" ]] && return 0
    [[ -n "${_filterby}" ]] && return 0
    local _separator && _separator="${1}"
    local _colspan && _colspan=$(echo "${_head}" | awk -F';' '{print NF}' | bc)
    echo "_separator;${_colspan};${_separator}" >> "${_output_temp}"
}

function shout2wily() {
    # what: CA Wily APM output
    if [[ "${_custom_wily_metric_path}" == "" ]]; then
        die 3 "wily variable"    
    fi

    touch "${_output_temp}.wily" 2> /dev/null || die 13 "_output_temp.wily" "write"
    local _host
    local _days
    while read -r INPUT; do
        _host=$(echo "${INPUT}" | cut -d':' -f1)
        [[ "${_host}" == "FILE" ]] && _host=$(echo "${INPUT}" | cut -d':' -f2 | cut -d';' -f1)
        _days=$(echo "${INPUT}" | cut -d';' -f4)
        [[ "${_days}" == "NA" ]] && _days=-1
        echo "<metric type=\"IntCounter\" name=\"${_custom_wily_metric_path}${_host}\" value=\"${_days}\" />" >> "${_output_temp}.wily"
    done < "${_output_temp}"

    # output the metrics 
    if [[ -z "${_output_file}" ]]; then
        cat "${_output_temp}.wily"
        "${_rm_cmd}" -f "${_output_temp}.wily"
    else
        mv "${_output_temp}.wily" "${_output_file}"
    fi
}

function shout2statsd() {
    # what: statsd output. suitable for datadog and influx
    if [[ "${_custom_statsd_metric_name}" == "" ]]; then
        die 3 "statsd variable"    
    fi

    touch "${_output_temp}.statsd" 2> /dev/null || die 13 "_output_temp.statsd" "write"
    local _host
    local _days
    while read -r INPUT; do
        _host=$(echo "${INPUT}" | cut -d':' -f1)
        [[ "${_host}" == "FILE" ]] && _host=$(echo "${INPUT}" | cut -d':' -f2 | cut -d';' -f1)
        _days=$(echo "${INPUT}" | cut -d';' -f4)
        [[ "${_days}" == "NA" ]] && _days=0
        echo "${_custom_statsd_metric_name}=${_host}:${_days}|g" >> "${_output_temp}.statsd"
    done < "${_output_temp}"

    # output the metrics 
    if [[ -z "${_output_file}" ]]; then
        cat "${_output_temp}.statsd"
        "${_rm_cmd}" -f "${_output_temp}.statsd"
    else
        mv "${_output_temp}.statsd" "${_output_file}"
    fi
}

function shout2cw() {
    # what: cloudwatch putmetrics
    if [[ "${_custom_cw_namespace}" == "" ]]; then
        die 3 "cloudwatch variable"    
    fi

    touch "${_output_temp}.cw" 2> /dev/null || die 13 "_output_temp.cw" "write"
    local _host
    local _days
    local _status
    while read -r INPUT; do
        _host=$(echo "${INPUT}" | cut -d':' -f1)
        [[ "${_host}" == "FILE" ]] && _host=$(echo "${INPUT}" | cut -d':' -f2 | cut -d';' -f1)
        _days=$(echo "${INPUT}" | cut -d';' -f4)
        [[ "${_days}" == "NA" ]] && _days=0
        _status=$(echo "${INPUT}" | cut -d';' -f2)
        echo "aws cloudwatch put-metric-data --metric-name \"${_host}\" --dimensions \"URL=${_host},Status=${_status}\" --namespace \"${_custom_cw_namespace}\" --value \"${_days}\" --unit \"days\" --timestamp $(date +%s)" >> "${_output_temp}.cw"
    done < "${_output_temp}"

    # output the metrics 
    if [[ -z "${_output_file}" ]]; then
        cat "${_output_temp}.cw"
        "${_rm_cmd}" -f "${_output_temp}.cw"
    else
        mv "${_output_temp}.cw" "${_output_file}"
    fi
}

function shout2esapm() {
    # what: elasticsearch metricset 
    if [[ ${#_custom_esapm_metricset[@]} -eq 0  ]]; then
        die 3 "esapm variable"    
    fi

    touch "${_output_temp}.esapm" 2> /dev/null || die 13 "_output_temp.esapm" "write"
    local _host
    local _days
    local _status
    while read -r INPUT; do
        _host=$(echo "${INPUT}" | cut -d':' -f1)
        [[ "${_host}" == "FILE" ]] && _host=$(echo "${INPUT}" | cut -d':' -f2 | cut -d';' -f1)
        _days=$(echo "${INPUT}" | cut -d';' -f4)
        [[ "${_days}" == "NA" ]] && _days=0
        _status=$(echo "${INPUT}" | cut -d';' -f2)
        echo "{ \"metricset\" : { \"tags\" : { \"${_custom_esapm_metricset[0]}\" : \"${_custom_esapm_metricset[1]}\", \"status\" : \"${_status}\" }, \"timestamp\" : \"$(date +%s)\",  \"samples\" : { \"days.${_host/./_}\" : { \"value\" : \"${_days}\" } } } }" >> "${_output_temp}.esapm"
    done < "${_output_temp}"

    # output the metrics 
    if [[ -z "${_output_file}" ]]; then
        cat "${_output_temp}.esapm"
        "${_rm_cmd}" -f "${_output_temp}.esapm"
    else
        mv "${_output_temp}.esapm" "${_output_file}"
    fi
}

function shout2prometheus() {
    # what: prometheus metrics
    if [[ ${#_custom_prometheus_metricset[@]} -eq 0  ]]; then
        die 3 "prometheus variable"    
    fi

    touch "${_output_temp}.prometheus" 2> /dev/null || die 13 "_output_temp.prometheus" "write"
    # include metadata?
    if [[ "${_custom_prometheus_metricset[0]}" == "true" ]]; then
        echo "# HELP ${_custom_prometheus_metricset[1]} SSL Certificates Days To Expiration" >> "${_output_temp}.prometheus"
        echo "# TYPE ${_custom_prometheus_metricset[1]} gauge" >> "${_output_temp}.prometheus"
    fi
    local _host
    local _days
    while read -r INPUT; do
        _host=$(echo "${INPUT}" | cut -d':' -f1)
        [[ "${_host}" == "FILE" ]] && _host=$(echo "${INPUT}" | cut -d':' -f2 | cut -d';' -f1)
        _days=$(echo "${INPUT}" | cut -d';' -f4)
        [[ "${_days}" == "NA" ]] && _days=0
        echo "${_custom_prometheus_metricset[1]}{endpoint=\"${_host}\"} ${_days} $(date +%s)" >> "${_output_temp}.prometheus"
    done < "${_output_temp}"

    # output the metrics 
    if [[ -z "${_output_file}" ]]; then
        cat "${_output_temp}.prometheus"
        "${_rm_cmd}" -f "${_output_temp}.prometheus"
    else
        mv "${_output_temp}.prometheus" "${_output_file}"
    fi
}

function shout2dxapm() {
    # what: elasticsearch metricset 
    if [[ ${#_custom_dxapm_metricset[@]} -eq 0 ]]; then
        die 3 "dxapm variable"    
    fi

    touch "${_output_temp}.dxapm" 2> /dev/null || die 13 "_output_temp.dxapm" "write"
    local _host
    local _days
    local _status
    while read -r INPUT; do
        _host=$(echo "${INPUT}" | cut -d':' -f1)
        [[ "${_host}" == "FILE" ]] && _host=$(echo "${INPUT}" | cut -d':' -f2 | cut -d';' -f1)
        _days=$(echo "${INPUT}" | cut -d';' -f4)
        [[ "${_days}" == "NA" ]] && _days=0
        _status=$(echo "${INPUT}" | cut -d';' -f2)
        # treat _status like nagios exit code
        case "${_status}" in
            "Valid")    _status=0;;
            "Expiring") _status=1;;
            "Expired")  _status=2;;
            *)          _status=3;;
        esac
        echo "{ \"agent\" : \"${_custom_dxapm_metricset[0]}\", \"host\" : \"$(hostname -s)\", \"metrics\" : [ { \"name\" : \"${_custom_dxapm_metricset[1]}:Days\", \"type\" : \"IntCounter\", \"value\" : \"${_days}\" },{ \"name\" : \"${_custom_dxapm_metricset[1]}:Status\", \"type\" : \"IntCounter\", \"value\" : \"${_status}\" } ] }" >> "${_output_temp}.dxapm"
    done < "${_output_temp}"

    # output the metrics 
    if [[ -z "${_output_file}" ]]; then
        cat "${_output_temp}.dxapm"
        "${_rm_cmd}" -f "${_output_temp}.dxapm"
    else
        mv "${_output_temp}.dxapm" "${_output_file}"
    fi
}

function shout2graphite() {
    # what: graphite metrics
    if [[ "${_custom_graphite_metric_name}" == "" ]]; then
        die 3 "graphite variable"    
    fi

    touch "${_output_temp}.graphite" 2> /dev/null || die 13 "_output_temp.graphite" "write"
    local _host
    local _days
    while read -r INPUT; do
        _host=$(echo "${INPUT}" | cut -d':' -f1)
        [[ "${_host}" == "FILE" ]] && _host=$(echo "${INPUT}" | cut -d':' -f2 | cut -d';' -f1)
        _days=$(echo "${INPUT}" | cut -d';' -f4)
        [[ "${_days}" == "NA" ]] && _days=0
        echo "${_custom_graphite_metric_name}.${_host/./_} ${_days} $(date +%s)" >> "${_output_temp}.graphite"
    done < "${_output_temp}"

    # output the metrics 
    if [[ -z "${_output_file}" ]]; then
        cat "${_output_temp}.graphite"
        "${_rm_cmd}" -f "${_output_temp}.graphite"
    else
        mv "${_output_temp}.graphite" "${_output_file}"
    fi
}

function shout() {
    # what: default shout. everything else comes from here.
    # print cert info to file. always handle it as csv then format afterwards, stupid? old-fashioned? 
    # sip. works better thou.
    # args: hostname[1] port[2] status[3] exp_date[4] days_lef[5] cert_issuer[6] cert_cn[7] cert_sn[8]

    # build the line
    local _line
    local _host="${1}"
        [[ -n "${_alt_label}" ]] && _host="${_alt_label}"
    local _port=":${2}"
        [[ -n "${_alt_label}" ]] && unset _port
    local _status="${3}"
    local _pretty_date="${4}" 
        ! [[ "${_pretty_date}" == "NA" ]] && _pretty_date=$(echo "${_certdate}" | awk '{ print $1, $2, $4 }')
    local _days_left="${5}"
    local _certissuer="${6}"
    local _certcn="${7}"
    local _certsn="${8}"
    unset _alt_label

    if [[ "${_outputSAN}" && "${_certSAN}" != "" ]]; then
        _port="${_port} (${_certSAN})"
    fi

    if [[ "${_local_notation}" == "true" ]]; then
        _port="${_port} (local)"
    fi

    case "${_extrafields_c}" in
        0) # default output
            _line="${_host}${_port};${_status};${_pretty_date};${_days_left}"
            ;;
        1) # issuer
            _line="${_host}${_port};${_certissuer};${_status};${_pretty_date};${_days_left}"
            ;;
        4) # issuer + cn
            _line="${_host}${_port};${_certissuer};${_certcn};${_status};${_pretty_date};${_days_left}"
            ;;
        9) # issuer + cn + serial
            _line="${_host}${_port};${_certissuer};${_certcn};${_certsn};${_status};${_pretty_date};${_days_left}" 
            ;;
        6) # issuer + serial
            _line="${_host}${_port};${_certissuer};${_certsn};${_status};${_pretty_date};${_days_left}" 
            ;;
        3) # cn
            _line="${_host}${_port};${_certcn};${_status};${_pretty_date};${_days_left}"
            ;;
        8) # cn + serial
            _line="${_host}${_port};${_certcn};${_certsn};${_status};${_pretty_date};${_days_left}"
            ;;
        5) # serial
            _line="${_host}${_port};${_certsn};${_status};${_pretty_date};${_days_left}"
            ;;
        *) # something went wrong, probably specified -e multiple times, so assume default output
            _line="${_host}${_port};${_status};${_pretty_date};${_days_left}"
            ;;
    esac

    # are there static fields? where should they be positioned?
    if [[ "${_static_field_exist}" -eq 1 ]]; then
        case "${_custom_static_fields_pos}" in
            "begin") 
                _line="${_static_fields};${_line}"
                ;;
            "end")
                _line="${_line};${_static_fields}"
                ;;
        esac
    fi
    echo "${_line}" >> "${_output_temp}"
}

function tuckdashirt_order() {
    # what: order the results
    # bail if order not set or depending on output type - what's the point for them?
    [[ -z "${_orderby}" || "${_outputtype}" =~ ^(json|cw|wily|dxapm|statsd|prometheus|graphite|esapm)$ ]] && return 0
    # get results file columns
    local _result_file_col && _result_file_col=$(grep -Ev "(^#|^$|^_separator)" "${_output_temp}" | head -1 | awk -F ';' '{print NF}' | bc)
    # determine if multiple columns were passed for ordering, first the easy part, one column to order by
    if [[ $(echo "${_orderby}" | grep -c "," | bc) -eq 0 ]]; then
        # column in range?
        local _orderby_y="${_orderby}"
        [[ "${_orderby_y}" =~ ^r ]] && _orderby_y="${_orderby_y:1:1}"
        [[ "${_orderby_y}" -gt "${_result_file_col}" ]] && return 0
        local _sort_cmd
        touch "${_output_temp}.resorted" 2> /dev/null || die 13 "_output_temp.resorted" "write"
        # build sort command - check if reverse order
        [[ "${_orderby}" =~ ^r ]] && _sort_cmd="sort -t\";\" -k${_orderby/r/} -r" || _sort_cmd="sort -t\";\" -k${_orderby}"
    else
        # now comes the headache - when multiple columns passed for order
        # lets split the var first and check if reverse was used
        local _orderby_a && _orderby_a="${_orderby%%,*}"
        [[ "${_orderby_a}" =~ ^r ]] && _orderby_a="${_orderby_a:1:1}" && local _reverse="true"
        local _orderby_b && _orderby_b="${_orderby##*,}"
        # column in range?
        [[ "${_orderby_a}" -gt "${_result_file_col}" || "${_orderby_b}" -gt "${_result_file_col}" ]] && return 0
        local _sort_cmd
        touch "${_output_temp}.resorted" 2> /dev/null || die 13 "_output_temp.resorted" "write"
        # build the ugly sort command
        if [[ "${_reverse}" == "true" ]]; then 
            _sort_cmd="sort -t\";\" -k${_orderby_a},${_orderby_a} -k${_orderby_b},${_orderby_b} -r"
        else
            _sort_cmd="sort -t\";\" -k${_orderby_a},${_orderby_a} -k${_orderby_b},${_orderby_b}"
        fi
    fi

    # build the ordered file
    if [[ "${_noheader}" == "true" ]]; then
        eval "${_sort_cmd}" "${_output_temp}" > "${_output_temp}.resorted"
        mv "${_output_temp}.resorted" "${_output_temp}"
    else
        head -1 "${_output_temp}" > "${_output_temp}.resorted"
        tail -n +2 "${_output_temp}" | eval "${_sort_cmd}" >> "${_output_temp}.resorted"
        mv "${_output_temp}.resorted" "${_output_temp}"
    fi
}

function tuckdashirt_filter() {
    # what: filter the results
    # bail if filter not set
    [[ -z "${_filterby}" ]] && return 0
    local _grep_cmd
    touch "${_output_temp}.filtered" 2> /dev/null || die 13 "_output_temp.filtered" "write"
    # build grep command - check if void or match
    [[ "${_filterby}" =~ ^- ]] && _grep_cmd="grep -v ${_filterby:1}" || _grep_cmd="grep ${_filterby:1}" 
    if [[ "${_noheader}" == "true" ]]; then
        eval "${_grep_cmd}" "${_output_temp}" > "${_output_temp}.filtered"
        mv "${_output_temp}.filtered" "${_output_temp}"
    else
        head -1 "${_output_temp}" > "${_output_temp}.filtered"
        tail -n +2 "${_output_temp}" | eval "${_grep_cmd}" >> "${_output_temp}.filtered"
        mv "${_output_temp}.filtered" "${_output_temp}"
    fi
}

function myhead() {
    # what: print header
    # ignore and arbitrary set to false if setting if html or json outputs were used
    # annnnnd ignore it again and set to true if using wily/influx/datadog/prometheus/etc output
    [[ "${_outputtype}" =~ ^(html|json)$ ]] && _noheader="false"
    [[ "${_outputtype}" =~ ^(cw|wily|dxapm|statsd|prometheus|graphite|esapm)$ ]] && _noheader="true" 
    # bail if dumping a cert
    [[ "${_certdump}" == "true" ]] && return 0
    # then finally bail if _noheader is set to true
    [[ "${_noheader}" == "true" ]] && return 0

    # otherwise build the header
    case "${_extrafields_c}" in
        0) # default output
            _head="Host;Status;Expires;Days"
            ;;
        1) # issuer
            _head="Host;Issuer;Status;Expires;Days"
            ;;
        4) # issuer + cn
            _head="Host;Issuer;CNAME;Status;Expires;Days"
            ;;
        9) # issuer + cn + serial
            _head="Host;Issuer;CNAME;Serial;Status;Expires;Days"
            ;;
        6) # issuer + serial
            _head="Host;Issuer;Serial;Status;Expires;Days"
            ;;
        3) # cn
            _head="Host;CNAME;Status;Expires;Days"
            ;;
        8) # cn + serial
            _head="Host;CNAME;Serial;Status;Expires;Days"
            ;;
        5) # serial
            _head="Host;Serial;Status;Expires;Days"
            ;;
        *) # something went wrong, probably specified -e multiple times, so assume default output
            _head="Host;Status;Expires;Days"
            ;;
    esac

    # are there static fields? where should they be positioned?
    if [[ "${_static_field_exist}" -eq 1 ]]; then
        local _addhead
        _addhead="${_custom_static_fields_names[*]}"
        _addhead="${_addhead// /;}"
        case "${_custom_static_fields_pos}" in
            "begin") 
                _head="${_addhead};${_head}"
                ;;
            "end")
                _head="${_head};${_addhead}"
                ;;
        esac
    fi
    echo "${_head}" > "${_output_temp}"
}

function pokeit() {
    # what: test connection to endpoint over bash tcp socket, runs by 4sec max
    # args: hostname[1]:port[2] OR hostname[1] port[2]

    # bail if proxy is in use, cant run tcp socket over proxy without much trouble
    [[ -n "${_openssl_proxy}" ]] && return 0

    local _addr="${1}"
    local _port="${2}"
    if [[ $(echo "${_addr}" | grep -c ":" | bc) -eq 1 ]]; then
        _port=$(echo "${_addr}" | cut -d":" -f2)
        _addr=$(echo "${_addr}" | cut -d":" -f1)
    fi
    if [[ $(LC_ALL=C type -t _timeout) == "function" ]]; then
        _timeout 4 bash -c "cat < /dev/null > /dev/tcp/${_addr}/${_port}" 2> /dev/null
    else
        timeout -s SIGINT 4s bash -c "cat < /dev/null > /dev/tcp/${_addr}/${_port}" 2> /dev/null
    fi
}

function servergut() { 
    # what: server gutter. grab certificate from endpoint
    # args: server[1] port[2]
    local _addr="${1}"
    local _port="${2}"
    local _res

    # hook into some default ports and define starttls/tls accordingly - may/may not break things - needs more testing
    case "${_port}" in
        smtp|25|submission|587) _tlsflag="-starttls smtp";; 
        pop3|110)               _tlsflag="-starttls pop3";;
        imap|143)               _tlsflag="-starttls imap";;
        ftp|21)                 _tlsflag="-starttls ftp";;
        xmpp|5222)              _tlsflag="-starttls xmpp";;
        xmpp-server|5269)       _tlsflag="-starttls xmpp-server";;
        irc|194)                _tlsflag="-starttls irc";;
        postgres|5432)          _tlsflag="-starttls postgres";;
        mysql|3306)             _tlsflag="-starttls mysql";;
        lmtp|24)                _tlsflag="-starttls lmtp";;
        nntp|119)               _tlsflag="-starttls nntp";;
        sieve|4190)             _tlsflag="-starttls sieve";;
        ldap|389)               _tlsflag="-starttls ldap";;
        # few makeshifts
        mongo|27017)            _tlsflag="-tls1";;
        *)                      _tlsflag="";;
    esac

    # build openssl options and command
    if [[ "${_tls_server_name}" == "false" ]]; then
        _openssl_options="-connect ${_addr}:${_port} ${_tlsflag}"
    else
        _openssl_options="-connect ${_addr}:${_port} -servername ${_addr} ${_tlsflag}"
    fi

    # add proxy arg if it exists
    if [[ -n "${_openssl_proxy}" ]]; then
        _openssl_options="-proxy ${_openssl_proxy} ${_openssl_options}"
    fi

    _opensslCMD="echo | openssl s_client ${_openssl_options} 2> ${_error_temp} 1> ${_cert_temp}"

    # test connection to the endpoint
    _res="true"
    if pokeit "${_addr}:${_port}"; then
        echo "" | eval "${_opensslCMD}"
    else
        _res="false"
    fi

    # hard to determine reachable when using proxy so force it
    ! [[ -s "${_cert_temp}" ]] && _res="false"

    # are we exporting chain?
    if [[ "${_res}" == "true" && "${_export_tag}" =~ ^(c|C)$ ]]; then
        _chain_temp=$(mktemp /tmp/"${_this//.sh/}"_chain_temp.XXXXXX 2> /dev/null) || die 13 "_chain_temp" "write"
        _openssl_options="-showcerts ${_openssl_options}"
        _opensslCMD="echo | openssl s_client ${_openssl_options} 2> /dev/null | tail -n +4 1> ${_chain_temp}"
        echo "" | eval "${_opensslCMD}"
        # sanitize chain temp output
        # head is clean already, so just find where last cert ends and reap from that point onwards
        local _end_cert && _end_cert=$(grep -n 'END CERTIFICATE' "${_chain_temp}" | tail -1 | cut -d':' -f1 | bc)
        sed -n "1,${_end_cert}p" "${_chain_temp}" > "${_chain_temp}.temp" || die 13 "_chain_temp" "write"
        mv "${_chain_temp}.temp" "${_chain_temp}"
    fi

    if [[ "${_res}" == "false" ]] > /dev/null; then
        if [[ "${_seek_local_certs}" == "true" ]]; then
            _local_cert="${_local_certs_path}/${_host}_${_port}.cer"
            if [[ -f "${_local_cert}" ]]; then
                _local_notation="true"
                unset _exportcert
                filegut "${_local_cert}" "${_addr}" "${_port}"
                unset _local_notation
            else
                shout "${_host}" "${_port}" "Unreachable" "NA" "NA" "NA" "NA" "NA"
            fi
        else
            shout "${_host}" "${_port}" "Unreachable" "NA" "NA" "NA" "NA" "NA"
        fi
    elif grep -i "ssl handshake failure" "${_error_temp}" > /dev/null; then
        shout "${_addr}" "${_port}" "SSL handshake failed" "NA" "NA" "NA" "NA" "NA"
    elif grep -i "no peer certificate available" "${_cert_temp}" > /dev/null; then
        shout "${_addr}" "${_port}" "No certificate" "NA" "NA" "NA" "NA" "NA"
    else
        filegut "${_cert_temp}" "${_addr}" "${_port}"
    fi
}

function urlgut() {
    # what: get the certificate from given URL when it's available as a downloable resource - ex http://foobar.com/files/SSLFile
    # args: URL[1]
    local _certurl && _certurl="${1}"

    ! [[ "${_certurl}" =~ ^https?://.* ]] && die 5

    _res="true"
    if [[ $(LC_ALL=C type -t _timeout) == "function" ]]; then
        if ! _timeout 5 wget -q -O "${_cert_temp}" "${_certurl}"; then
            _res="false"
        fi
    else
        if ! timeout -s SIGINT 5s wget -q -O "${_cert_temp}" "${_certurl}"; then
            _res="false"
        fi
    fi    

    [[ -s "${_cert_temp}" ]] || _res="false"
    # from local to global
    _host=$(echo "${_certurl}" | sed "s/http.*:\/\///g")

    if [[ "${_res}" == "false" ]] > /dev/null; then
        if [[ "${_seek_local_certs}" == "true" ]]; then
            _local_cert="${_local_certs_path}/${_host//\//_}.cer"
            if [[ -f "${_local_cert}" ]]; then
                _local_notation="true"
                unset _exportcert
                filegut "${_local_cert}" "URL" "${_host}"
                unset _local_notation
            else
                shout "URL" "${_host}" "Unreachable" "NA" "NA" "NA" "NA" "NA"
            fi
        else
            shout "URL" "${_host}" "Unreachable" "NA" "NA" "NA" "NA" "NA"
        fi
    else
        filegut "${_cert_temp}" "URL" "${_host}"
    fi
}

function filegut() {
    # what: check cert file. common parser for local/remote. every cert info is actually read from here.
    # args: cert_file[1] server[2] port[3]
    local _certfile="${1}"
    local _host="${2}"
    local _port="${3}"

    # check if the file is a SAML IdP Metadata XML, if so parse it to extract the cert
    if grep -q "EntityDescriptor" "${_certfile}" 2> /dev/null || grep -q "X509Certificate" "${_certfile}" 2> /dev/null; then
        # build a cert file out of the XML
        echo '-----BEGIN CERTIFICATE-----' > "${_cert_temp}.saml"
        tr '>' '\n' < "${_certfile}" | sed '/X509Certificate/,/<\/.*X509Certificate/!d;/<\/.*X509Certificate/q' | sed 's/<.*X509Certificate//g' | grep -v "^$" >> "${_cert_temp}.saml"
        echo '-----END CERTIFICATE-----' >> "${_cert_temp}.saml"
        # reap empty lines out of it - if any
        grep -E -v '(^ *#|^ *$)' "${_cert_temp}.saml" > "${_cert_temp}" 
        eval "${_rm_cmd}" "${_cert_temp}.saml"
        # sometimes IdP has a long line cert instead of 64bytes, in that case break it so openssl can parse it without issue
        if [[ $(head -2 "${_cert_temp}" | tail -1 | wc -c | bc) -gt 65 ]]; then
            fold -w64 "${_cert_temp}" > "${_cert_temp}.fold"
            mv "${_cert_temp}.fold" "${_cert_temp}"
        fi
        local _saml="${_certfile}"
        _certfile="${_cert_temp}"
    fi

    # check if cert is DER, if so convert it
    if openssl x509 -inform der -in "${_certfile}" -outform pem -out /dev/null 2> /dev/null ; then
        openssl x509 -inform der -in "${_certfile}" -outform pem -out "${_cert_temp}.PEM"
        mv "${_cert_temp}.PEM" "${_cert_temp}"
        local _der="${_certfile}"
        _certfile="${_cert_temp}"
    fi

    # check if file is PEM, is readable and higher than 0bytes
    if [[ ! -r "${_certfile}" ]] || [[ ! -s "${_certfile}" ]]; then
        if [[ "${_host}" == "FILE" ]]; then
            _certfile="${_certfile##*/}"
        elif [[ "${_host}" == "URL" ]]; then
            _certfile="${_certurl}"
        fi
        shout "${_host}" "${_certfile}"  "File not found" "NA" "NA" "NA" "NA" "NA"
        return 0
    # it all failed
    elif ! openssl x509 -noout -in "${_certfile}" 2> /dev/null; then
        if [[ "${_host}" == "FILE" ]]; then
            _certfile="${_certfile##*/}"
        elif [[ "${_host}" == "URL" ]]; then
            _certfile="${_certurl}"
        fi
        shout "${_host}" "${_certfile}" "Invalid Certificate" "NA" "NA" "NA" "NA" "NA"
        return 0
    fi

    # is it just a dump?
    if [[ "${_certdump}" == "true" ]]; then
        local _certdump_data
        local _line_data
        local _needle _needle=("Version:" "Serial Number:" "Issuer:" "Subject:" "Not Before.*" "Not After.*" "X509v3 Extended Key Usage:" "X509v3 Subject Alternative Name:" "Full Name" "Authority Information Access:")
        openssl x509 -in "${_certfile}" -text -noout 2> /dev/null | sed -e '/:$/N;s/\n//;/: $/N;s/\n//' > "${_cert_temp}.seded"
        mv "${_cert_temp}.seded" "${_cert_temp}"
        _certdump_data="Certificate: ${_certfile##*/}\n"
        [[ -n "${_der}" ]] && _certdump_data="Certificate: ${_der##*/}\n"     
        [[ -n "${_saml}" ]] && _certdump_data="Certificate: ${_saml##*/}\n"
           for _i in "${_needle[@]}"; do
            _line_data=$(grep "${_i}" "${_cert_temp}" | xargs)
            [[ "${_line_data:0:5}" == "Not B" ]] && _line_data="\nValid ${_line_data}"
            [[ "${_line_data:0:5}" == "Not A" ]] && _line_data="Valid ${_line_data}\n"
            [[ "${_line_data:0:9}" == "Full Name" ]] && _line_data="\nCRL Distribution Point ${_line_data}"
            [[ "${_line_data:0:28}" == "Authority Information Access" ]] && _line_data="CRL ${_line_data}"
            [[ -n "${_line_data}" ]] && _certdump_data="${_certdump_data}${_line_data}\n"
        done
        echo -e "${_certdump_data}" #| sed "s/: /;: /g" | column -t -s';'
        return 0
    fi

    # get expiration date
    _certdate=$(openssl x509 -in "${_certfile}" -enddate -noout -inform pem | cut -d'=' -f2)
    # get issuer
    [[ "${_show_issuer}" == "true" ]] && _certissuer=$(openssl x509 -in "${_certfile}" -issuer -noout -inform pem | awk 'BEGIN { RS="=" } END { print $1}') 
    # get CN/subject - is it really worth?
    [[ "${_show_cn}" == "true" ]] && _certcn=$(openssl x509 -in "${_certfile}" -subject -noout -inform pem | awk 'BEGIN { RS="=" } END { print $1}')
    # get serial - pfff bogus
    [[ "${_show_serial}" == "true" ]] && _certsn=$(openssl x509 -in "${_certfile}" -serial -noout -inform pem | cut -d'=' -f2)

    # get SANs?
    if [[ "${_outputSAN}" ]]; then
        _certSAN=$(openssl x509 -in "${_certfile}" -noout -text -inform pem | grep -A1 "X509v3 Subject Alternative Name" | grep -v X509v3 | xargs)
    fi

    # make an array out of cert date and get julian
    local _date_array=()
    read -r -a _date_array <<< "${_certdate}"
    _global_month=$(gimmemonth "${_date_array[0]}")

    # convert date to secs and get diff from now to expiration date
    _certjulian=$(gimmejulian "${_global_month#0}" "${_date_array[1]#0}" "${_date_array[3]}")
    _certdiff=$(datediff "${_now_julian}" "${_certjulian}")

    if [[ "${_host}" == "FILE" ]]; then _port=$(echo "${_port}" | awk -F '/' '{print $NF}'); fi

    if [[ "${_certdiff}" -lt 0 ]]; then
        # cert is expired
        shout "${_host}" "${_port}" "Expired" "${_certdate}" "${_certdiff}" "${_certissuer}" "${_certcn}" "${_certsn}"
    elif [[ "${_certdiff}" -lt "${_warning_notice}" ]]; then
        # cert is soon to expire or diff equals zero
        if [[ "${_certdiff}" -ne 0 ]]; then 
            shout "${_host}" "${_port}" "Expiring" "${_certdate}" "${_certdiff}" "${_certissuer}" "${_certcn}" "${_certsn}"
        else
            shout "${_host}" "${_port}" "Expired" "${_certdate}" "${_certdiff}" "${_certissuer}" "${_certcn}" "${_certsn}"
        fi
    else
        # cert is valid
        shout "${_host}" "${_port}" "Valid" "${_certdate}" "${_certdiff}" "${_certissuer}" "${_certcn}" "${_certsn}"
    fi
}

# main routine
# bail if no argument is given
[[ "${#}" -eq 0 ]] && quickhelp && die 0
# show manual if invoked
[[ "${1}" == "manual" ]] && manual | less -r && die 0

# otherwise get command line options/arguments
while getopts ":mine:SdE:f:l:t:o:p:s:u:O:F:Pxv" _cmd_option; do
    case "${_cmd_option}" in
        # context type
        # by host
        s) _host="${OPTARG}"
            [[ -n "${_fqdn_file}" || -n "${_certurl}" || -n "${_certfile}" || -n "${_orderby}" || -n "${_filterby}" ]] && die 5
            ;;
        p) _port="${OPTARG}"
            [[ -n "${_fqdn_file}" || -n "${_certurl}" || -n "${_certfile}" || -n "${_orderby}" || -n "${_filterby}" ]] && die 5
            ;;
        # by local file
        f) _certfile="${OPTARG}"
            [[ -n "${_fqdn_file}" || -n "${_certurl}" || -n "${_port}" || -n "${_host}" || -n "${_orderby}" || -n "${_filterby}" ]] && die 5
            ! [[ -r "${_certfile}" ]] && die 13 "${_certfile}" "find"
            ;;
        # by list
        l) _fqdn_file="${OPTARG}"
            [[ -n "${_host}" || -n "${_certurl}" || -n "${_port}" || -n "${_certfile}" ]] && die 5
            ! [[ -r "${_fqdn_file}" ]] && die 13 "${_fqdn_file}" "find"
            ;;
        u) _certurl="${OPTARG}"
            [[ -n "${_host}" || -n "${_fqdn_file}" || -n "${_port}" || -n "${_certfile}" ]] && die 5
            ;;
        n) _noheader="true";;
        # formatting
        # extra fields
        e) _extrafields="${OPTARG}"
            [[ "${_outputtype}" =~ ^(cw|wily|dxapm|statsd|prometheus|graphite|esapm)$ ]] && unset _extrafields && continue
            if echo "${_extrafields}" | sed "s/\,/\n/g" | grep -vE "(^|,)(issuer|cn|subject|serial)($|,)" > /dev/null; then
                die 5
            fi
            _extrafields="${_extrafields//subject/cn}"
            for i in ${_extrafields//,/ }; do
                [[ "${i}" == "issuer" ]] && _show_issuer="true" && _extrafields_c=$((_extrafields_c +1))
                [[ "${i}" == "cn" ]] && _show_cn="true" && _extrafields_c=$((_extrafields_c + 3))
                [[ "${i}" == "serial" ]] && _show_serial="true" && _extrafields_c=$((_extrafields_c + 5))
            done
            ;;
        # show SAN
        S) _outputSAN="true"
            ;;
        d) _certdump="true"
            [[ -n "${_outputtype}" || -n "${_fqdn_file}" || -n "${_certurl}" || -n "${_port}" || -n "${_host}" || -n "${_orderby}" || -n "${_filterby}" ]] && die 5
            ;;
        # order by
        o) _orderby="${OPTARG}"
            [[ -z "${_fqdn_file}" || -n "${_host}" || -n "${_port}" || -n "${_certfile}" ]] && die 5
            ! [[ "${_orderby}" =~ ^r?[0-9]{1,2}$|^r?[1-9]{1,2},[1-9]{1,2}$ ]] && die 5
            ;;
        # filter by
        F) _filterby="${OPTARG}"
            [[ -z "${_fqdn_file}" || -n "${_host}" || -n "${_port}" || -n "${_certfile}" ]] && die 5
            ;;
        # save results to file
        O) _output_file="${OPTARG}"
            [[ "${_shootmail}" == "true" || "${_instrumentme}" == "true" ]] && die 5
            touch "${_output_file}" 2> /dev/null || die 13 "${_output_file}" "write"
            ;;
        # output type
        t) _outputtype="${OPTARG}"
            if ! [[ "tty csv html json cw wily dxapm statsd prometheus graphite esapm" =~ (^|[[:space:]])$_outputtype($|[[:space:]]) ]]; then
                die 5
            fi
            [[ "${_outputtype}" =~ ^(cw|wily|dxapm|statsd|prometheus|graphite|esapm)$ ]] && unset _extrafields && continue
            ;;
        # misc
        # Export cert to
        E) _exportcert="true"
            _export_tag="${OPTARG}"
            [[ -n "${_fqdn_file}" || -n "${_certfile}" ]] && die 5
            ! [[ "${_export_tag}" =~ ^(c|C)$ ]] && die 5
            if ! [[ -d "${_local_certs_path}" ]]; then
                mkdir "${_local_certs_path}" 2> /dev/null || die 13 "_local_certs_path" "write"
            fi
            [[ "${_export_tag}" =~ ^(c|C)$ && -n "${_certurl}" ]] && die 5 
            ;;
        # send mail
        m) _shootmail="true"
            [[ -n "${_output_file}" || "${_instrumentme}" == "true" ]] && die 5
            _output_file=$(mktemp /tmp/"${_this//.sh/}"_output_mail.XXXXXX 2> /dev/null) || die 13 "_output_mail" "write"
            # it uses either telnet or sendmail so check if they're available
            if [[ "${_custom_mail_usealtmechanism[0]}" == "true" ]]; then
                zitheer telnet || die 3 "telnet"
            else
                zitheer sendmail || die 3 "sendmail"
            fi
            # check mail vars
            if [[ "${_custom_mail_from}" == "" || "${_custom_mail_to}" == "" || "${_custom_mail_subject}" == "" ]]; then
                die 3 "email variable"    
            fi
            ;;
        # instrument
        i) _instrumentme="true"
            [[ -n "${_output_file}" || "${_shootmail}" == "true" ]] && die 5
            _output_file=$(mktemp /tmp/"${_this//.sh/}"_output_instrument.XXXXXX 2> /dev/null) || die 13 "_output_instrument" "write"
            ;;
        P) _showprogress="true"
            [[ -z "${_fqdn_file}" || -n "${_host}" || -n "${_port}" || -n "${_certfile}" ]] && die 5
            # get rid of it if running non-interactively - some may use it on cron for ex - it happens
            [[ -n "${PS1}" ]] && unset _showprogress
            ;;
        # debug
        x) set -x
            _rm_cmd=$(command -v true)
            ;;
        # version
        v) echo "${_my_version}" && die 0 ;;
        # anything else
        :) # missing arg
            # is it on the 'E' optional flag?
            if [[ "${OPTARG}" == "E" ]]; then
                _exportcert="true"
                [[ -n "${_fqdn_file}" || -n "${_certfile}" ]] && die 5
                if ! [[ -d "${_local_certs_path}" ]]; then
                    mkdir "${_local_certs_path}" 2> /dev/null || die 13 "_local_certs_path" "write"
                fi
                continue
            else
                quickhelp && die 1
            fi
            ;;
        \?) quickhelp && die 1;;
        \*) quickhelp && die 1;;
    esac
done

# if we got to this point, go ahead and set the ground
groundset

# enough chitchat and do the job. parse command line and do the thing.
if [[ -n "${_host}" ]]; then
    # if running against host
    myhead
    servergut "${_host}" "${_port:=443}"
elif [[ -f "${_fqdn_file}" ]]; then
    # using FQDN file
    # valdate fqdn file
    if ! fqdnshape; then
        die 15 "${_fqdn_file}"
    fi
    myhead
    # define vars for progress bar
    _start=1 && _end=$(grep -c -Ev "(^#|^$)" "${_fqdn_file}" | bc)
    # no static fields - pretty straightforward
    if [[ "${_static_field_exist}" -eq 0 ]]; then 
    while IFS= read -r LINE; do
        # is this line a separator?
        if [[ "${LINE:0:10}" == "_separator" ]]; then
            gimmespace "${LINE##*;}"
            continue
        fi
        _host="${LINE%% *}"
        _port="${LINE##* }"
        # using alt label?
        [[ "${_host}" == *";"* ]] && _alt_label=$(echo "${_host}" | cut -d';' -f1) && _host=$(echo "${_host}" | cut -d';' -f2)
        # gut it
        # show progress?
        if [[ "${_showprogress}" == "true" ]]; then
            whatsmaprogress "${_start}" "${_end}" && ((_start++)) 
        else
            unset _start _end
        fi
        if [[ "$_port" = "FILE" ]]; then
            filegut "${_host}" "FILE" "${_host}"
        elif [[ "$_port" = "URL" ]]; then
            urlgut "${_host}"
        else
            servergut "${_host}" "${_port}"
        fi 
    done < <(grep -Ev "(^#|^$)" "${_fqdn_file}")
    # with static fields, here comes the trouble
    else
        # build an array out of LINE, exclude last 2, that are host/port - or should be - whatever lefts over are static fields
        while IFS= read -r LINE; do
            # is this a separator?
            if [[ "${LINE:0:10}" == "_separator" ]]; then
                gimmespace "${LINE##*;}"
                continue
            fi
            read -r -a LINE_ <<< "${LINE}"
            _host="${LINE_[${#LINE_[@]} - 2]}"
            _port="${LINE_[${#LINE_[@]} - 1]}"
            # using alt label?
            [[ "${_host}" == *";"* ]] && _alt_label=$(echo "${_host}" | cut -d';' -f1) && _host=$(echo "${_host}" | cut -d';' -f2)
            # remove last 2 elements from the array
            unset "LINE_[${#LINE_[@]} - 1]" && unset "LINE_[${#LINE_[@]} - 1]"
            # LINE_ now is an array worth of static fields only, concat and convert to string
            _static_fields="${LINE_[*]}"
            _static_fields="${_static_fields// /;}"
            # gut it
            # show progress?
            if [[ "${_showprogress}" == "true" ]]; then
                whatsmaprogress "${_start}" "${_end}" && ((_start++)) 
            else
                unset _start _end
            fi
            if [[ "$_port" = "FILE" ]]; then
                filegut "${_host}" "FILE" "${_host}"
            elif [[ "$_port" = "URL" ]]; then
                urlgut "${_host}"
            else
                servergut "${_host}" "${_port}"
            fi
        done < <(grep -Ev "(^#|^$)" "${_fqdn_file}")
    fi
elif [[ -n "${_certfile}" ]]; then
    # running against local cert file
    myhead
    filegut "${_certfile}" "FILE" "${_certfile}"
elif [[ -n "${_certurl}" ]]; then
    # running against URL
    myhead
    urlgut "${_certurl}"
else
    # all errors should be handled already, but ya never know the perks of dealing with user interaction
    quickhelp && die 1 "You’ll have to speak up. I’m wearing a towel."
fi

# at this point, we have the results already. so treat theam as requested
# output ordered or filtered?
[[ -n "${_orderby}" ]] && tuckdashirt_order
[[ -n "${_filterby}" ]] && tuckdashirt_filter

# woof show or mail results and finally, die
case "${_outputtype}" in
    "tty")
        shout2console
        ;;
    "csv")
        shout2csv
        ;;
    "json")
        shout2json
        ;;
    "html")
        shout2html
        ;;
    "wily")
        shout2wily
        ;;
    "statsd")
        shout2statsd
        ;;
    "prometheus")
        shout2prometheus
        ;;
    "cw")
        shout2cw
        ;;
    "graphite")
        shout2graphite
        ;;
    "esapm")
        shout2esapm
        ;;
    "dxapm")
        shout2dxapm
        ;;
    *)
        _outputtype="tty"
        shout2console
        ;;
esac

# check if it should be emailled, injected or notthing... 
if [[ "${_shootmail}" == "true" ]]; then
    shout2mail
    eval "${_rm_cmd}" -f "${_output_file}"
elif [[ "${_instrumentme}" == "true" ]]; then
    shout2instrument
    eval "${_rm_cmd}" -f "${_output_file}"
fi
# should we just save the cert? theeeen die.
if [[ "${_exportcert}" == "true" && -s "${_cert_temp}" ]]; then
    [[ -n "${_certurl}" ]] && _exportcert="${_local_certs_path}/${_host//\//_}.cer" || _exportcert="${_local_certs_path}/${_host}_${_port}.cer"
    if [[ "${_export_tag}" == "c" ]]; then
        _exportcert="${_local_certs_path}/${_host}_${_port}_chain.cer"
        mv "${_chain_temp}" "${_exportcert}"
    elif [[ "${_export_tag}" == "C" ]]; then
        _exportcert="${_local_certs_path}/${_host}_${_port}"
        touch /tmp/_chain_temp_{1,2,3}.cer 1> /dev/null 2> /dev/null || die 13 "_chain_temp" "write"
        awk 'BEGIN { i=1; file="/tmp/_chain_temp_"i".cer" } /BEGIN CERTIFICATE/,/END CERTIFICATE/ { print >file } /END CERTIFICATE/{ i++; file="/tmp/_chain_temp_"i".cer" }' "${_chain_temp}"
        mv /tmp/_chain_temp_1.cer "${_exportcert}_server.cer"
        mv /tmp/_chain_temp_2.cer "${_exportcert}_intermediate.cer"
        mv /tmp/_chain_temp_3.cer "${_exportcert}_root.cer"
    else

        mv "${_cert_temp}" "${_exportcert}"
    fi
fi
die 0
