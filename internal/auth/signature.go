package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

// VerifySignatureは、本文と、届いた署名が
// 秘密の値を使って計算した結果と、一致するかを確認する。
func VerifySignature(secret, body []byte, signature string) bool {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	expected := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(expected), []byte(signature))
}

// 知らなかったので学びメモへ
// - :=は変数を使って、値を入れるを一行で書く記号
// hmacとは、HMACの計算をする道具です。それがmacに入る。
// sha256を使うと指定する。secretは計算するために必要は秘密の値。
// mac.Writeでbody本文を渡す。
// mac.Sum(nil)→計算結果を取り出す。mac.Writeでは計算してない
// 計算結果をbase64にエンコード。これが結果。
// expectedとsignatureを比較して返す。
// ==で比較してはいけない。タイミング攻撃のリスクがあるため。
// つまり、==で比較しても書けるけど、安全性を考えると適していないということかな？
