#!/usr/bin/perl

#------ 初期設定 ----------------------------------------------------------

#■日本語コード変換ライブラリ
use lib '../cgi';
use Jcode;

#■SENDMAILの設定
$sendmail = '/usr/lib/sendmail';


#■受信先メールアドレス
my %mailto=(
		stampon => {
				'title' => 'スタンポン',
				'addr' => 'stampon_info@ftl2.onmicrosoft.com',
				'form_val' => 'スタンポン'
		},
		others => {
				'title' => 'その他',
				'addr' => 'gyoumu@ftl2.onmicrosoft.com',
				'form_val' => 'その他'
		},
);


#■名称
$title = '【重要】スタンポンお問い合わせ';

#■処理画面のボディ設定
$body = '<body bgcolor="#ffffff">';

#■記入者申告メールアドレス( name="email"の時 )未入力でも送信する  1:する 0:しない
$mailcheck = 0;

#--------------------------------------------------------------------------

#時刻取得
($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time);
$wday = ('SUN','MON','TUE','WED','THU','FRI','SAT')[$wday];
$date_now = sprintf("%02d/%02d %s %02d:%02d",$mon +1,$mday,$wday,$hour,$min);

#タイトル欄に入力がない場合のデフォルト値
$subject = "- NO SUBJECT -";

#データ入力
if ($ENV{'REQUEST_METHOD'} ne "POST") { &error('エラー','標準入力 METHOD=POST を設定してください.<br>&lt;form method=post action=........&gt;'); }
read(STDIN, $buffer, $ENV{'CONTENT_LENGTH'});
if ($buffer eq '') { &error('エラー','このＣＧＩは直接起動されません.'); }
$ref = $ENV{'HTTP_REFERER'};
$buffer2 = $ENV{'QUERY_STRING'};
if ($buffer2 ne '') { &error('エラー','標準入力 METHOD=POST に設定してください.<br>&lt;form method=post action=........&gt;'); }

#デコード
@pairs = split(/&/,$buffer);
foreach $pair (@pairs) {

	($name,$value) = split(/=/,$pair);
	$value =~ tr/+/ /;
	$value =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C",hex($1))/eg;
	$name =~ tr/+/ /;
	$name =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C",hex($1))/eg;

	&Jcode::convert(*name,'sjis'); &Jcode::convert(*value,'sjis');

	if ($value =~ /\r\n/) { $value =~ s/\r//g; }
	elsif ($value =~ /\r/) { $value =~ s/\r/\n/g; }

	if ($name eq "location") { $lct = $value; }
	elsif ($name eq "c_copy" && $value eq "on") { $cc = "on"; }
	elsif ($name eq "no_check" && $value eq "on") { $nocheck = "on"; }
	elsif ($name eq "space_check" && $value eq "on") { $spcheck = "on"; }
	elsif ($name eq "no_check") { ; }
	elsif ($name eq "ref_url") { $ref_url = $value; }
	elsif ($name eq "ref_name") { $ref_name = $value; }
	elsif ($name eq "subject" && $value ne "") { $subject = $value; }
	elsif ($name eq "subject") { ; }
	elsif ($name eq "ref_page") { $ref = $value; }
	elsif ($name eq "password") {

		$password = $value;
		push(@DATA_N,$name);
		push(@DATA_V,$value);
	}
	elsif ($name eq "Submit") {

		$Submit = $value;
		push(@DATA_N,$name);
		push(@DATA_V,$value);
	}
	else {

		if ($name =~ /^email/i || $name =~ /^e\-mail/i) {

			$value =~ s/　/ /g;
			if ($value =~ / / || $value =~ /;/) { $value = ""; }
			if (!($value =~ /(.*)\@(.*)\.(.*)/)) { $value = ""; }

			$email = $value;
		}

		if ($name eq "mailto") {
			for my $my_key(keys %mailto){
				if ($value eq $mailto{$my_key}->{form_val}) { $mailto = $mailto{$my_key}->{addr}; $my_chk=1;}
			}
			if(! $my_chk){ &error("回答が正しくありません"); }
		}

		push(@DATA_N,$name); push(@DATA_V,$value);

		$name =~ s/\</&lt;/g; $value =~ s/\</&lt;/g;
		$name =~ s/\>/&gt;/g; $value =~ s/\>/&gt;/g;
		$name =~ s/\"/&quot;/g; $value =~ s/\"/&quot;/g;
		push(@DATA_NS,$name); push(@DATA_VS,$value);
	}
}

#入力チェック
if (!$mailcheck && $email eq '') { &error('Ｅメールアドレスを入力してください',''); }
if ($mailcheck && $email eq '') { $email = 'anonymous@on.the.net'; }
if ($spcheck eq "on") {	foreach (@DATA_V) { if ($_ eq "") { &error('送信不可','受信者の意向により、全ての項目を埋めないと送信できません.'); } }}
for(keys %mailto){
if ($mailto{$_}->{addr} eq '' || !($mailto{$_}->{addr} =~ /(.*)\@(.*)/)) { &error('設定ミス','受信先メールアドレスが設定されていません.'); }
}
 
if ($nocheck eq "on") { &sendmail; }




#内容確認画面出力
print "Content-type: text/html; charset=UTF-8\n\n";
print "

<html><head><title>$title</title></head>



$body
<h1>内容確認</h1>
<form method=\"post\" action=\"webform2.cgi\">
<blockquote>
<table border=0 cellpadding=3 cellspacing=3>
<tr><td bgcolor=\"#CBE7FF\" width=\"130\"><b><font size=+1>項目</font></b></td><td bgcolor=\"#CBE7FF\" width=\"450\"><b><font size=+1>内容</font></b></td></tr>

";

$count = @DATA_NS;

foreach (0..$count-1) {

	print "<input type=hidden name=\"$DATA_NS[($_)]\" value=\"$DATA_VS[($_)]\">\n";

	if($DATA_NS[($_)] eq 'mailto'){
		$my_atrb='お問い合わせ内容';
		for my $my_key (keys %mailto){
			if($DATA_VS[($_)] eq $mailto{$my_key}->{form_val}){ $my_val=$mailto{$my_key}->{title}; }
		}
	}else{
		$my_atrb=$DATA_NS[($_)];
		$my_val=$DATA_VS[($_)];
		#お問い合わせ内容は表示しない
		print "<tr><td bgcolor=\"#f0f0f0\">$my_atrb <br></td>";
	 
		if ($my_val =~ /\n/) { print "<td bgcolor=\"#ffffff\">$my_val</td></tr>\n"; }
		else { print "<td bgcolor=\"#ffffff\">$my_val</td></tr>\n"; }

	}
}

print "</table></blockquote><p>\n";

if ($lct ne "") { print "<input type=hidden name=\"location\" value=\"$lct\">\n"; }

print "<input type=hidden name=\"no_check\" value=\"on\">\n";
print "<input type=hidden name=\"ref_page\" value=\"$ref\">\n";

if ($cc eq "on") { print "<input type=hidden name=\"c_copy\" value=\"on\">\n"; }
if ($ref_url ne "") { print "<input type=hidden name=\"ref_url\" value=\"$ref_url\">\n"; }
if ($ref_name ne "") { print "<input type=hidden name=\"ref_name\" value=\"$ref_name\">\n"; }
if ($subject ne "") { print "<input type=hidden name=\"subject\" value=\"$subject\">\n"; }
if ($password ne "") { print "<input type=hidden name=\"password\" value=\"$password\">\n"; }
if ($mailto ne "") { print "<input type=hidden name=\"mailto\" value=\"$mailto\">\n"; }

if ($email eq '') { print "<font size=+2><b>メールアドレスを入力しないと送信できません</b></font><p>\n"; }
else { print "<img src=\"../img/s.gif\" width=\"180\" height=\"1\"><input type=submit value=\"　送信 -submit-　\"><p>\n"; }

print "</form><p>\n";
print "<p></body></html>\n";
exit;

sub sendmail {

if (!(open(OUT,"| $sendmail -fapache\@ftl.co.jp -t"))) { &error('システム異常','申し訳ありませんが何らかの原因で処理できません.'); }

    #if (!(open(OUT, ">> sendmail_test.txt"))) { &error('システム異常','申し訳ありませんが何らかの原因で処理できません.'); }
	print OUT "X-Mailer: WebFORM v4.0 by www.rescue.ne.jp\n";
	print OUT "X-HTTP_REFERER: $ref\n";
	print OUT "Errors-To: $mailto\n";
	print OUT "To: $mailto\n";
	print OUT "From: $email\n";
	&jis("Subject: $subject"); print OUT "$msg\n";
	print OUT "Content-Transfer-Encoding: 8bit\n";
	print OUT "Content-Type: text/plain\; charset=\"UTF-8\"\n\n\n";

	&jis("--- ここから ---"); print OUT "$msg\n\n";

	$count = @DATA_N;
	foreach (0..$count-1) {

#ここから
		if($DATA_V[($_)] eq 'gyoumu@ftl.co.jp'){
			print OUT "\n";
			}
		elsif($DATA_V[($_)] eq 'jinji@ftl.co.jp'){
			print OUT "\n";
			}
		elsif($DATA_V[($_)] eq 'srs_info@ftl.co.jp'){
			print OUT "\n";
			}
		elsif($DATA_N[($_)] eq 'mailto'){
			#print OUT "お問い合わせ選択 = $DATA_V[$_]\n";
			}
		elsif($DATA_N[($_)] eq 'Submit'){
			print OUT "\n";
			}
#ここまで 

		elsif ($DATA_V[$_] =~ /\n/) { &jis("$DATA_N[$_] =\n\n$DATA_V[$_]\n"); print OUT "$msg\n"; }
		else { &jis("$DATA_N[$_] = $DATA_V[$_]"); print OUT "$msg\n"; }
	}

	&jis("--- ここまで ---"); print OUT "\n$msg\n\n";

	$host = $ENV{'REMOTE_HOST'};
	$addr = $ENV{'REMOTE_ADDR'};
	if ($host eq $addr) { $host = gethostbyaddr(pack('C4',split(/\./,$host)),2) || $addr; }

	print OUT "\n";
	print OUT "----------------------------------------\n";
	print OUT "Processed         : $date_now\n";
	print OUT "Server-Name       : $ENV{'SERVER_NAME'}\n";
	print OUT "Server-Protocol   : $ENV{'SERVER_PROTOCOL'}\n";
	print OUT "Server-Port       : $ENV{'SERVER_PORT'}\n";
	print OUT "Gateway-Interface : $ENV{'GATEWAY_INTERFACE'}\n";
	print OUT "Request-Method    : $ENV{'REQUEST_METHOD'}\n";
	print OUT "Script-Name       : $ENV{'SCRIPT_NAME'}\n";
	print OUT "HTTP-Referer      : $ref\n";
	print OUT "HTTP-User-Agent   : $ENV{'HTTP_USER_AGENT'}\n";
	print OUT "Remote-host       : $host\n";
	print OUT "Remote-Addr       : $ENV{'REMOTE_ADDR'}\n";
	print OUT "----------------------------------------\n";
	print OUT "\n";

	close(OUT);

	if ($cc eq "on" && $lct ne '') {

		print "Content-type: text/html; charset=UTF-8\n\n";
		print "<html><head><title>$title</title></head>\n";
		print "$body\n";
		print "<h1>送信完了</h1>\n";
		print "ただ今送信された内容は以下の通りです.<br>\n";
		print "内容の写しとしてお控えください.<p>\n";
		print "<form>\n";
		print "<blockquote>\n";
		print "<textarea cols=70 rows=20>";
		&cc;
		print "</textarea></form></blockquote><p>\n";
		print "<h3>[<a href=\"$lct\" target=\"_top\">トップページへ戻る</a>]</h3>";
	}
	elsif ($cc eq "on") {

		print "Content-type: text/html; charset=UTF-8\n\n";
		print "<html><head><title>$title</title></head>\n";
		print "$body\n";
		print "<h1>送信完了</h1>\n";
		print "ただ今<a href=\"mailto:$mailto\">$mailto</a>宛てに送信された内容は以下の通りです.<br>\n";
		print "内容の写しとしてお控えください.<p>\n";
		print "<form>\n";
		print "<blockquote>\n";
		print "<textarea cols=70 rows=20>";
		&cc;
		print "</textarea></form></blockquote><p>\n";
		if ($ref_url ne '' && $ref_name ne '') { &Jcode::convert(*ref_name,'sjis'); print "<h3>[<a href=\"$ref_url\" target=\"_top\">$ref_name</a>]</h3>"; }
		print "</body></html>\n";
	}
	elsif ($lct ne '') { print "Location: $lct\n\n"; }
	else {
		print "Content-type: text/html; charset=UTF-8\n\n";
        	print "<html><head><title>$title</title></head>\n";
        	print "$body\n";
		print "<H1>送信完了</H1>\n";
		print "<p>お問い合わせありがとうございました。</p>\n";
		if ($ref_url ne '' && $ref_name ne '') { &Jcode::convert(*ref_name,'sjis'); print "<h3>[<a href=\"$ref_url\" target=\"_top\">$ref_name</a>]</h3>"; }
		print "<p></body></html>\n";
	}
	exit;
}

sub cc {

#	print "X-Processed: $date_now\n";
#	print "X-HTTP_REFERER: $ref\n";
#	print "X-HTTP-User-Agent: $ENV{'HTTP_USER_AGENT'}\n";
#	print "X-Remote-host: $host \[$ENV{'REMOTE_ADDR'}\]\n";
#	print "To: $mailto\n";
#	print "Subject: $subject\n\n";

	foreach (0..$count-1) {


		$DATA_NS[$_] =~ s/\</&lt;/g;
		$DATA_NS[$_] =~ s/\>/&gt;/g;
		$DATA_NS[$_] =~ s/\"/&quot;/g;

		$DATA_VS[$_] =~ s/\</&lt;/g;
		$DATA_VS[$_] =~ s/\>/&gt;/g;
		$DATA_VS[$_] =~ s/\"/&quot;/g;

#ここから
		if($DATA_VS[($_)] eq 'gyoumu@ftl.co.jp'){
			print "\n";
			}
		elsif($DATA_VS[($_)] eq 'jinji@ftl.co.jp'){
			print "\n";
			}
		elsif($DATA_VS[($_)] eq 'srs_info@ftl.co.jp'){
			print "\n";
			}
		elsif($DATA_NS[($_)] eq 'mailto'){
			#print "お問い合わせ内容 = $DATA_VS[$_]\n";
			}
		elsif($DATA_NS[($_)] eq 'Submit'){
			print "\n";
			}
#ここまで 
		elsif ($DATA_VS[$_] =~ /\n/) { print "$DATA_NS[$_] =\n$DATA_VS[$_]\n"; }
		else { print "$DATA_NS[$_] = $DATA_VS[$_]\n"; }
		
	}
}

sub jis { $msg = $_[0]; &Jcode::convert(*msg, 'jis'); }

sub error {

	print "Content-type: text/html; charset=UTF-8\n\n";
        print "<html><head><title>$title</title></head>\n";
        print "$body\n";
        print "<h1>$_[0]</h1>\n";
	print "<h3>$_[1]</h3>\n";

	if ($ref eq '') {

		print "※ フォームページが取得できません.<br>\n";
		print "※ ブラウザの[戻る]ボタンを押して前の画面に移動してください.<p>\n";
	}
	else {

		print "※ <a href=\"$ref\">フォームページ</a>へ戻るか、ブラウザの[戻る]ボタンを押して前の画面に移動してください.<p>\n";
	}

	print "<p></body></html>\n";
	exit;
}
