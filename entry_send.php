<?php
// 文字化け防止
header("Content-Type: text/html; charset=UTF-8");

// メール送信先（適宜変更）
$to = "jinji@ftl2.onmicrosoft.com";

// フォームからの入力値を取得（サニタイズ）
$name = htmlspecialchars($_POST['name'] ?? '', ENT_QUOTES, 'UTF-8');
$furigana = htmlspecialchars($_POST['furigana'] ?? '', ENT_QUOTES, 'UTF-8');
$school = htmlspecialchars($_POST['school'] ?? '', ENT_QUOTES, 'UTF-8');
$faculty = htmlspecialchars($_POST['faculty'] ?? '', ENT_QUOTES, 'UTF-8');
$department = htmlspecialchars($_POST['department'] ?? '', ENT_QUOTES, 'UTF-8');
$grade = htmlspecialchars($_POST['grade'] ?? '', ENT_QUOTES, 'UTF-8');
$phone = htmlspecialchars($_POST['phone'] ?? '', ENT_QUOTES, 'UTF-8');
$email = htmlspecialchars($_POST['email'] ?? '', ENT_QUOTES, 'UTF-8');
$email_confirm = htmlspecialchars($_POST['email_confirm'] ?? '', ENT_QUOTES, 'UTF-8');
$positions = $_POST['desired_position'] ?? [];
$motivation = htmlspecialchars($_POST['motivation'] ?? '', ENT_QUOTES, 'UTF-8');
$self_pr = htmlspecialchars($_POST['self_pr'] ?? '', ENT_QUOTES, 'UTF-8');
$remarks = htmlspecialchars($_POST['remarks'] ?? '', ENT_QUOTES, 'UTF-8');
$wk=implode(', ', array_map('htmlspecialchars', $positions));
// メールアドレス確認チェック
if ($email !== $email_confirm) {
    echo "メールアドレスが一致しません。戻って修正してください。";
    exit;
}

// 必須チェック（簡易）
if (empty($name) || empty($school) || empty($grade) || empty($email) || empty($motivation) || empty($positions)) {
    echo "必須項目が未入力です。戻って修正してください。";
    exit;
}

// メール本文作成
$subject = "【学生エントリー】{$name} 様より";
$body = <<<EOD
学生エントリーシートの内容：

■ 氏名：{$name}
■ ふりがな：{$furigana}
■ 学校名：{$school}
■ 学部：{$faculty}
■ 学科：{$department}
■ 学年：{$grade}
■ 電話番号：{$phone}
■ メールアドレス：{$email}
■ 希望職種：{$wk}
■ 志望動機：
{$motivation}

■ 自己PR：
{$self_pr}

■ 備考：
{$remarks}
EOD;

// メール送信（送信者のアドレスを From に設定）
$headers = "From: {$email}\r\n";

// メール送信実行
$success = mb_send_mail($to, $subject, $body, $headers);

// 結果表示
if ($success) {
    echo "送信が完了しました。ありがとうございました。";
} else {
    echo "送信に失敗しました。しばらくしてから再度お試しください。";
}

header("Location: thanks.html");
exit;
?>
