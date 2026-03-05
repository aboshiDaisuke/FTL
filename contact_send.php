<?php
// 文字コード設定（日本語対応）
mb_language("Japanese");
mb_internal_encoding("UTF-8");

// POSTデータの取得・サニタイズ
$category = isset($_POST['category']) ? implode(", ", $_POST['category']) : '';
$name     = htmlspecialchars($_POST['name'], ENT_QUOTES, 'UTF-8');
$phone    = htmlspecialchars($_POST['phone'], ENT_QUOTES, 'UTF-8');
$email    = htmlspecialchars($_POST['email'], ENT_QUOTES, 'UTF-8');
$message  = htmlspecialchars($_POST['message'], ENT_QUOTES, 'UTF-8');

// メール送信先
$to = "gyoumu@ftl2.onmicrosoft.com";  // ← あなたの受信したいメールアドレスに書き換えてください

// メール件名と本文
$subject = "【お問い合わせ】未来技術研究所Webフォームより";
$body = <<<EOT
以下の内容でお問い合わせを受け付けました。

【お問い合わせ種別】
{$category}

【お名前】
{$name}

【電話番号】
{$phone}

【メールアドレス】
{$email}

【お問い合わせ内容】
{$message}

EOT;

// 送信元設定
$headers = "From: {$email}";

// メール送信処理
if (mb_send_mail($to, $subject, $body, $headers)) {
  echo "お問い合わせありがとうございました。送信が完了しました。";
} else {
  echo "送信に失敗しました。しばらくしてから再度お試しください。";
}

header("Location: thanks.html");
exit;
?>
