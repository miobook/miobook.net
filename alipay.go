package controllers

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"github.com/revel/revel"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	/** 支付宝消息验证地址 */
	HTTPS_VERIFY_URL = "https://mapi.alipay.com/gateway.do?service=notify_verify&"
	//支付宝网关地址
	ALIPAY_GATEWAY_NEW = "http://wappaygw.alipay.com/service/rest.htm?"
)

var alipayConfig *AlipayConfig

type AliPayWap struct { //
	*revel.Controller
}

//支付宝支付接口 
func (p AliPayWap) Pay(orderCode string) revel.Result {

	domain_path := "http://miobook.net" //自己的域名地址

	format := "xml"

	v := "2.0"

	req_id := string(time.Now().Nanosecond())

	//服务器异步通知页面路径
	notify_url := domain_path + "/mobile/alipay/notifyurl"
	//页面跳转同步通知页面路径
	call_back_url := domain_path + "/mobile/alipay/callbackurl"
	//操作中断返回地址
	merchant_url := domain_path + "/mobile/alipay/notpay"

	//卖家支付宝帐户
	seller_email := "miobook.net@msn.com"

	//商户订单号
	out_trade_no := orderCode  

	subject := "纳尼！"

	total_fee := "0.01"

	req_dataToken := "<direct_trade_create_req><notify_url>" + notify_url + "</notify_url><call_back_url>" + call_back_url + "</call_back_url><seller_account_name>" + seller_email + "</seller_account_name><out_trade_no>" + out_trade_no + "</out_trade_no><subject>" + subject + "</subject><total_fee>" + total_fee + "</total_fee><merchant_url>" + merchant_url + "</merchant_url></direct_trade_create_req>"

	sParaTempToken := make(map[string]string)
	sParaTempToken["service"] = "alipay.wap.trade.create.direct"
	sParaTempToken["format"] = format
	sParaTempToken["v"] = v
	sParaTempToken["partner"] = alipayConfig.partner
	sParaTempToken["req_id"] = req_id
	sParaTempToken["sec_id"] = alipayConfig.sign_type
	sParaTempToken["sign"] = "" // 参数绑定时会重新赋值

	sParaTempToken["req_data"] = req_dataToken

	sParaTempToken["_input_charset"] = alipayConfig.input_charset

	abc := ALIPAY_GATEWAY_NEW

	//建立请求
	sHtmlTextToken := p.buildRequestFilePost(abc, "", "", sParaTempToken)

	sHtmlTextToken, _ = url.QueryUnescape(sHtmlTextToken)

	request_token := p.getRequestToken(sHtmlTextToken)

	//业务详细
	req_data := "<auth_and_execute_req><request_token>" + request_token + "</request_token></auth_and_execute_req>"  

	//把请求参数打包成数组
	sParaTemp := make(map[string]string)
	sParaTemp["service"] = "alipay.wap.auth.authAndExecute"
	sParaTemp["partner"] = alipayConfig.partner
	sParaTemp["_input_charset"] = alipayConfig.input_charset
	sParaTemp["sec_id"] = alipayConfig.sign_type
	sParaTemp["format"] = format
	sParaTemp["v"] = v
	sParaTemp["req_data"] = req_data

	//组装自动提交From表单HTML
	sHtmlText := p.buildRequestHtml(ALIPAY_GATEWAY_NEW, sParaTemp, "get", "确认")
	sHtmlText = fmt.Sprintf("<!DOCTYPE html><html><body>%s</body></html>", sHtmlText)

	p.Response.Out.Write([]byte(sHtmlText))
	return nil

}

/**
 * 支付宝同步回调地址 
 */
func (p AliPayWap) CallBackURL(out_trade_no, request_token, result, trade_no, sign, sign_type string) revel.Result {

	params := make(map[string]string)
	params["out_trade_no"] = out_trade_no
	params["request_token"] = request_token
	params["result"] = result
	params["trade_no"] = trade_no
	params["sign"] = sign
	params["sign_type"] = sign_type

	verify_result := p.verifyReturn(params)

	if verify_result { //验证成功
		//TODO
		revel.TRACE.Println("验证成功<br />")
		//TODO
	} else {
		//TODO
		revel.TRACE.Println("验证失败")
	}
	return p.RenderText(PrintReqParams(p.Params.Values))
}

/**
 * 支付宝异步通知地址 
 */
func (p AliPayWap) NotifyURL() revel.Result {

	if p.Request.Method != "POST" {
		return nil
	}

	params := make(map[string]string)
	PostForm, _ := ParsePostForm(p.Request)

	revel.TRACE.Println("支付宝异步通知NotifyURL PostForm:\n\n\n" + PrintReqParams(PostForm))

	for key, values := range PostForm {
		params[key] = ""
		if len(values) > 0 {
			params[key] = values[0]
		}
	}

	decrypt_params := params
	if alipayConfig.sign_type == "0001" {
		decrypt_params = p.decrypt(params)
	}

	doc_notify_data := decrypt_params["notify_data"]

	notify := new(AlipayNotify)

	XmlToObj(doc_notify_data, notify)

	//out_trade_no := notify.Out_trade_no

	//trade_no := notify.Trade_no

	trade_status := notify.Trade_status

	revel.TRACE.Printf("\n notify  %v  \n\n\n", notify)

	if p.verifyNotify(params, notify.Notify_id) { //验证成功

		if trade_status == "TRADE_FINISHED" {
			//TODO
			revel.TRACE.Println("+++++++++++++++++success")
			p.Response.Out.Write([]byte("success"))

		} else if trade_status == "TRADE_SUCCESS" {
			//TODO
			revel.TRACE.Println("++++++++++++++++++++success")
			p.Response.Out.Write([]byte("success"))
		}

	} else { //验证失败
		//TODO
		revel.TRACE.Println("+++++++++++++++++++++++++fail")
		p.Response.Out.Write([]byte("fail"))
	}

	return nil
}

//支付中断通知地址 
func (p AliPayWap) NotPay() revel.Result {
	revel.ERROR.Println("\n\n\n支付中断通知NotPay:" + PrintReqParams(p.Params))
	return p.RenderText(" 支付中断通知NotPay:" + PrintReqParams(p.Params.Values))
}

/**
 * 除去数组中的空值和签名参数
 */
func (p AliPayWap) paraFilter(sArray map[string]string) map[string]string {

	result := make(map[string]string, 0)

	if len(sArray) <= 0 {
		return result
	}

	for key, value := range sArray {
		if value == "" || len(value) == 0 || strings.ToLower(key) == "sign" || strings.ToLower(key) == "sign_type" {
			continue
		}
		result[key] = value
	}

	return result
}

/**
 * 把数组所有元素排序，并按照“参数=参数值”的模式用“&”字符拼接成字符串
 */
func (p AliPayWap) createLinkString(params map[string]string) string {

	prestr := ""
	keys := []string{}
	for key, _ := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for i := 0; i < len(keys); i++ {
		key := keys[i]
		value := params[key]
		if i == (len(keys) - 1) {
			prestr = prestr + key + "=" + value
		} else {
			prestr = prestr + key + "=" + value + "&"
		}

	}
	revel.TRACE.Printf("\n\n\n[[[%v]]]\n\n\n", prestr)

	return prestr
}

/**
 * 把数组所有元素按照固定参数排序，以“参数=参数值”的模式用“&”字符拼接成字符串
 */
func (p AliPayWap) createLinkStringNoSort(params map[string]string) string {

	prestr := ""

	sParaSort := make(map[string]string, 0)
	sParaSort["service"] = params["service"]
	sParaSort["v"] = params["v"]
	sParaSort["sec_id"] = params["sec_id"]
	sParaSort["notify_data"] = params["notify_data"]

	for key, value := range sParaSort {
		prestr = prestr + key + "=" + value + "&"
	}

	rs := []rune(prestr)
	end := len(rs)
	end = end - 1
	prestr = string(rs[0:end])

	return prestr
}

/**
 * 写日志
 */
func (p AliPayWap) logResult(sWord string) {

}

/**
 * 验证消息是否是支付宝发出的合法消息，验证callback
 */
func (p AliPayWap) verifyReturn(params map[string]string) bool {
	sign := ""
	sign = params["sign"]

	isSign := p.getSignVeryfy(params, sign, true)
	return isSign
}

/**
 * 验证消息是否是支付宝发出的合法消息，验证服务器异步通知
 */
func (p AliPayWap) verifyNotify(params map[string]string, notify_id string) bool {

	if alipayConfig.sign_type == "0001" {
		params = p.decrypt(params)
	}

	responseTxt := "true"
	responseTxt = p.verifyResponse(notify_id)

	sign := ""
	sign = params["sign"]
	isSign := p.getSignVeryfy(params, sign, false)

	if isSign && responseTxt == "true" {
		return true
	}
	return false
}

/**
 * 解密
 */
func (p AliPayWap) decrypt(inputPara map[string]string) map[string]string {

	inputPara["notify_data"] = RSA_decrypt(inputPara["notify_data"], alipayConfig.private_key, alipayConfig.input_charset)

	return inputPara
}

/**
 * 根据反馈回来的信息，生成签名结果
 */
func (p AliPayWap) getSignVeryfy(Params map[string]string, sign string, isSort bool) bool {

	sParaNew := p.paraFilter(Params)

	preSignStr := ""
	if isSort {
		preSignStr = p.createLinkString(sParaNew)
	} else {
		preSignStr = p.createLinkStringNoSort(sParaNew)
	}

	isSign := false
	if alipayConfig.sign_type == "MD5" {
		isSign = MD5_verify(preSignStr, sign, alipayConfig.key, alipayConfig.input_charset)
	} else if alipayConfig.sign_type == "0001" {
		isSign = RSA_verify(preSignStr, sign, alipayConfig.ali_public_key, alipayConfig.input_charset)
	}
	return isSign
}

/**
 * 获取远程服务器ATN结果,验证返回URL
 */
func (p AliPayWap) verifyResponse(notify_id string) string {

	partner := alipayConfig.partner
	veryfy_url := HTTPS_VERIFY_URL
	param := make(map[string]string)
	param["partner"] = partner
	param["notify_id"] = notify_id

	return p.checkUrl(veryfy_url, param)

}

/**
 * 获取远程服务器ATN结果
 */
func (p AliPayWap) checkUrl(url string, values map[string]string) string {
	byes, _, yes, _ := HttpPost(url, values, nil)
	if yes {
		return string(byes)
	}
	return ""
}

/**
 * 生成签名结果
 */
func (p AliPayWap) buildRequestMysign(sPara map[string]string) string {
	prestr := p.createLinkString(sPara)
	mysign := ""
	if alipayConfig.sign_type == "MD5" {
		mysign = MD5_sign(prestr, alipayConfig.key, alipayConfig.input_charset)
	}
	if alipayConfig.sign_type == "0001" {
		mysign = RSA_sign(prestr, alipayConfig.private_key, alipayConfig.input_charset)
	}
	return mysign
}

/**
 * 生成要请求给支付宝的参数数组
 */
func (p AliPayWap) buildRequestPara(sParaTemp map[string]string) map[string]string {

	sPara := p.paraFilter(sParaTemp)

	mysign := p.buildRequestMysign(sPara)

	sPara["sign"] = mysign

	if sPara["service"] != "alipay.wap.trade.create.direct" && sPara["service"] != "alipay.wap.auth.authAndExecute" {
		sPara["sign_type"] = alipayConfig.sign_type
	}

	return sPara
}

/**
 * 建立请求，以表单HTML形式构造（默认）
 */
func (p AliPayWap) buildRequestHtml(ALIPAY_GATEWAY_NEW string, sParaTemp map[string]string, strMethod string, strButtonName string) string {

	sPara := p.buildRequestPara(sParaTemp)

	sbHtml := "<form id=\"alipaysubmit\" name=\"alipaysubmit\" action=\"" + ALIPAY_GATEWAY_NEW + "_input_charset=" + alipayConfig.input_charset + "\" method=\"" + strMethod + "\">"

	for name, value := range sPara {
		sbHtml = sbHtml + "<input type=\"hidden\" name=\"" + name + "\" value=\"" + value + "\"/>"
	}

	sbHtml = sbHtml + "<input type=\"submit\" value=\"" + strButtonName + "\" style=\"display:none;\"></form>"
	sbHtml = sbHtml + "<script>document.forms['alipaysubmit'].submit();</script>"

	return sbHtml
}

/**
 * 建立请求
 */
func (p AliPayWap) buildRequestFilePost(ALIPAY_GATEWAY_NEW string, strParaFileName, strFilePath string, sParaTemp map[string]string) string {

	sPara := p.buildRequestPara(sParaTemp)
	byes, err, yes, status := HttpPost(ALIPAY_GATEWAY_NEW, sPara, nil)

	if err != nil {
		revel.ERROR.Printf("=====%v=====%v===%v==", string(byes), err, yes, status)
	}

	return string(byes)

}

type NameValuePair struct {
	Key   string
	Value string
}

/**
 * MAP类型数组转换成NameValuePair类型
 */
func (p AliPayWap) generatNameValuePair(properties map[string]string) []*NameValuePair {
	nameValuePair := make([]*NameValuePair, 0)

	for key, value := range properties {
		nameValuePair = append(nameValuePair, &NameValuePair{Key: key, Value: value})
	}

	return nameValuePair
}

/**
 * 解析远程模拟提交后返回的信息，获得token
 */
func (p AliPayWap) getRequestToken(text string) string {
	request_token := ""
	strSplitText := strings.Split(text, "&")

	paraText := make(map[string]string, 0)

	tokenbegin := "<request_token>"
	tokenend := "</request_token>"

	for _, one := range strSplitText {

		K_V := strings.Split(one, "=")

		if len(K_V) == 2 {
			paraText[K_V[0]] = K_V[1]
		} else if strings.Contains(one, tokenbegin) {

			b := strings.Index(one, tokenbegin) + len(tokenbegin)
			e := strings.Index(one, tokenend)

			rs := []rune(one)
			paraText["res_data"] = string(rs[b:e])
		}
	}

	request_token = paraText["res_data"]

	if alipayConfig.sign_type == "0001" {
		request_token = RSA_decrypt(request_token, alipayConfig.private_key, alipayConfig.input_charset)
	}

	return request_token
}

/**xml解析为结构体*/
func XmlToObj(xmlstr string, result interface{}) bool {
	input := []byte(xmlstr)
	err := xml.Unmarshal(input, result)
	if err != nil {
		return true
	}
	return false
}

//返回MD5加密
func Md5(s string) string {
	h := md5.New()
	h.Write([]byte(s))
	rs := hex.EncodeToString(h.Sum(nil))
	return rs
}

/**
 * 对签名字符串进行验证 （验证对方发送的签名）
 */
func MD5_verify(text, sign, key, input_charset string) bool {
	text = text + key
	mysign := Md5(text)
	if mysign == sign {
		return true
	}
	return false
}

/**
 * 对字符串进行签名
 */
func MD5_sign(text, key, input_charset string) string {
	text = text + key
	return Md5(text)
}

/**
* RSA签名
 */
func RSA_sign(content, privateKey, input_charset string) string {
	//TODO
	return ""
}

/**
* 解密
 */
func RSA_decrypt(content, private_key, input_charset string) string {
	//TODO
	return ""
}

/**
* RSA验签名检查
 */
func RSA_verify(content, sign, ali_public_key, input_charset string) bool {
	//TODO
	return false
}

// 发起Post请求
func HttpPost(urlstr string, form map[string]string, header map[string]string) ([]byte, error, bool, int) {

	yes := true
	var e error

	sendUrl := urlstr
	client := &http.Client{}
	reqest, _ := http.NewRequest("POST", sendUrl, nil)

	if form != nil && len(form) > 0 {
		postValues := url.Values{}
		for postKey, PostValue := range form {
			postValues.Set(postKey, PostValue)
		}
		postDataStr := postValues.Encode()
		postDataBytes := []byte(postDataStr)

		postBytesReader := bytes.NewReader(postDataBytes)
		reqest, _ = http.NewRequest("POST", sendUrl, postBytesReader)
		reqest.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")

	}

	if header != nil && len(header) > 0 {
		for key, value := range header {
			reqest.Header.Set(key, value)
		}
	}

	resp, err := client.Do(reqest)
	if err != nil {
		yes = false
		e = err
	}

	respBytes, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()

	return respBytes, e, yes, resp.StatusCode

}

/**解析Post Form data*/
func ParsePostForm(request *revel.Request) (vs url.Values, errstr string) {
	var reader io.Reader = request.Body
	b, e := ioutil.ReadAll(reader)
	defer request.Body.Close()
	LogErr(e)

	post := string(b)

	vs, eee := url.ParseQuery(post)
	_, errstr = LogErr(eee)
	return
}

/***/
func PrintReqParams(Params interface{}) string {
	return fmt.Sprintf("======%v", Params)
}

//
type AlipayConfig struct {

	// 合作身份者ID，以2088开头由16位纯数字组成的字符串
	partner string

	// 交易安全检验码，由数字和字母组成的32位字符串  如果签名方式设置为“MD5”时，请设置该参数
	key string

	// 商户的私钥  如果签名方式设置为“0001”时，请设置该参数
	private_key string

	// 支付宝的公钥  如果签名方式设置为“0001”时，请设置该参数
	ali_public_key string

	// 调试用，创建TXT日志文件夹路径
	log_path string

	// 字符编码格式 目前支持  utf-8
	input_charset string //"utf-8";

	// 签名方式，选择项：0001(RSA)、MD5
	sign_type string //"0001";

}

type AlipayNotify struct {
	Notify              string `xml:"notify"`
	Payment_type        string `xml:"payment_type"`
	Subject             string `xml:"subject"`
	Trade_no            string `xml:"trade_no"`
	Buyer_email         string `xml:"buyer_email"`
	Gmt_create          string `xml:"gmt_create"`
	Notify_type         string `xml:"notify_type"`
	Quantity            string `xml:"quantity"`
	Out_trade_no        string `xml:"out_trade_no"`
	Notify_time         string `xml:"notify_time"`
	Seller_id           string `xml:"seller_id"`
	Trade_status        string `xml:"trade_status"`
	Is_total_fee_adjust string `xml:"is_total_fee_adjust"`
	Total_fee           string `xml:"total_fee"`
	Gmt_payment         string `xml:"gmt_payment"`
	Seller_email        string `xml:"seller_email"`
	Price               string `xml:"price"`
	Buyer_id            string `xml:"buyer_id"`
	Notify_id           string `xml:"notify_id"`
	Use_coupon          string `xml:"use_coupon"`
}

func init() {
	alipayConfig = new(AlipayConfig)

	alipayConfig.partner = "My ID" ///

	alipayConfig.key = "My key" ///

	alipayConfig.private_key = ""

	alipayConfig.ali_public_key = ""

	alipayConfig.log_path = ""

	alipayConfig.input_charset = "utf-8"

	alipayConfig.sign_type = "MD5"

}
