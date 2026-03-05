#!/usr/bin/perl
#------------------------------------------------------
#  Copyright (C) 2002-2008 oyoyon All Rights Reserved.
#  http://www9.plala.or.jp/oyoyon/
#------------------------------------------------------
use strict;

use CGI qw(:cgi);
use CGI::Carp qw(fatalsToBrowser);

$CGI::POST_MAX = 300;
$CGI::DISABLE_UPLOADS = 1;
#------------------------------------------------------
my $Version = 'v1.511';
my $SessionLevel = 0;
my $P3P = '';

my $cfg_file = './downcfg.cgi';
(-e $cfg_file && -r $cfg_file) || die $!;
require $cfg_file;

my $FileDir = $down_cfg::FileDir;
my $LogDir = $down_cfg::LogDir;
my $DownLog = $down_cfg::DownLog;
my $ErrLog = $down_cfg::ErrLog;
my $LogSplitMode = $down_cfg::LogSplitMode;
my $LogSplitSize = $down_cfg::LogSplitSize;
my $LogSave = $down_cfg::LogSave;
my $AdminMailto = $down_cfg::AdminMailto;
my $SendmailPath = $down_cfg::SendmailPath;
my $TotalCountFile = $down_cfg::TotalCountFile;
my $LoginLogFile = $down_cfg::LoginLogFile;
my $RowIndexFormat = $down_cfg::RowIndexFormat;
my $AdminPass = $down_cfg::AdminPass;
my(@AllowLoginDomain) = @down_cfg::AllowLoginDomain;
my $ViewTotalCount = $down_cfg::ViewTotalCount;
my $LineFeedChange = $down_cfg::LineFeedChange;
my $UrlDirectory = $down_cfg::UrlDirectory;
my(@UrlFileList) = @down_cfg::UrlFileList;
my(%AliasFileName) = %down_cfg::AliasFileName;
my(%AddMime) = %down_cfg::AddMime;
my $SetReferer = $down_cfg::SetReferer;
my $DownloadLimit = $down_cfg::DownloadLimit;
my $NeedCookie = $down_cfg::NeedCookie;
my $WaitTime = $down_cfg::WaitTime;
my $DenyIPFile = $down_cfg::DenyIPFile;
my $UnRecErrorCode = $down_cfg::UnRecErrorCode;
my $SetPage = $down_cfg::SetPage;
#------------------------------------------------------
my(%MIMETYPE) = (
	"\.(?:bin|exe|lzh)" => "octet-stream",
	"\.bmp" => "image/bmp",
	"\.doc" => "msword",
	"\.gif" => "image/gif",
	"\.hqx" => "mac-binhex40",
	"\.jpe?g" => "image/jpeg",
	"\.midi?" => "audio/midi",
	"\.mp3" => "audio/mpeg",
	"\.mpe?g" => "video/mpeg",
	"\.pdf" => "pdf",			# x-pdf
	"\.png" => "image/png",
	"\.ppt" => "vnd.ms-powerpoint",
	"\.sit" => "x-stuffit",
	"\.swf" => "x-shockwave-flash",
	"\.txt" => "text/plain",
	"\.wav" => "audio/x-wav",
	"\.xls" => "vnd.ms-excel",
	"\.zip" => "x-zip-compressed"		# zip
);
(%MIMETYPE) = (%MIMETYPE, %AddMime) if (%AddMime);
#------------------------------------------------------
my $query = new CGI;
(my $setpage = ($SetPage || $ENV{'REQUEST_URI'} || $ENV{'SCRIPT_NAME'})) =~ s/\?.*$//;
my $ipaddr = $query->remote_addr;
my $SessionName = ($SessionLevel) ? sprintf("%02x%02x%02x%02x", split(/\./, $ipaddr)) : "dlsession";
my $filename = name_check();
my $count = download_file($filename);
logging($DownLog, $filename, $count);
exit;
#------------------------------------------------------
#======================================================
#	ファイル名チェック
#======================================================
sub name_check {
	# URL モード
	my $url = $query->param('url') || $query->path_info;
	if ($url) {
		($UrlDirectory && $UrlDirectory =~ /^https?:\/\/.+\/$/) || error("403 Forbidden", 3, "Invalid URL Mode");
		($url =~ /^[!\$%&'\(\)\*\+,\-\.\/\w:;=\?\@~]+$/) || error("400 Bad Request", 3, "URI Character");

		# パスチェック
		$url =~ s/^\///;
		($url =~ /[\.\/]+\//) && error("400 Bad Request", 3, "Path Name");

		# ファイル名の取得とチェック
		(my $filename = $url) =~ s/(?:.*\/)?([^\/]+)$/$1/;
		($filename =~ /^[-\.\w]+\.[0-9A-Za-z]+$/) || error("400 Bad Request", 3, "File Name");
		if (@UrlFileList) {
			my $allow;
			foreach (@UrlFileList) {
				next unless ($_ && $filename eq $_);
				$allow = 1; last;
			}
			($allow) || error("404 Not Found", 1, $filename);
		}
		else {
			my $allow;
			while (my($ext, undef) = each(%MIMETYPE)) {
				next unless ($ext && $filename =~ /$ext$/i);
				$allow = 1; last;
			}
			($allow) || error("405 Unsupported Media Type", 1, $filename);
		}

		my($dlcount, $cookie) = count_check($url, 1);
		restrict_check();
		logging($DownLog, $filename, $dlcount);
		redirectHeader($cookie, "$UrlDirectory$url");
	}

	# 通常モード
	my $name = $query->param('name');
	unless ($name) {
		# 総ダウンロード数の公開
		if ($ViewTotalCount && $query->param('c')) {
			mainHeader();
			mainHTML("Download Ranking");
			total_downloads();
			mainFooter(3);
		}

		# 入力パスワード取得
		my $passwd = $query->param('passwd');
		if ($passwd) {
			# ログイン制限
			if (@AllowLoginDomain) {
				my $allow;
				my $host = gethostbyaddr(pack("C4", split(/\./, $ipaddr)), 2) || $ipaddr;
				foreach (@AllowLoginDomain) {
					(my $str = $_) =~ s/\*/\.\+/g;
					if ($ipaddr =~ /^$str/ || $host =~ /$str$/) {
						$allow = 1; last;
					}
				}
				($allow) || error("403 Forbidden", 3, "Login Limit");
			}

			# 入力パスワード暗号化
			($passwd =~ /^\w+$/) || error("401 Unauthorized", 3, "NG Character");
			my(@salt) = ("0".."9", "A".."Z", "a".."z", ".", "/");
			my $DES = $salt[int(rand(64))] . $salt[int(rand(64))];
			my $MD5 = '$1$' . $DES . join("", map { $salt[int(rand(64))]; } (0..5)) . '$';
			$passwd = (crypt($passwd, $MD5) =~ /^\$1\$.*/) ? $& : crypt($passwd, $DES);
		}

		# クッキー取得
		my(%COOKIE) = $query->cookie(-name=>$SessionName);
		$passwd ||= $COOKIE{'P'};

		# パスワード認証
		unless ($passwd) {
			mainHeader();
			mainHTML();
			print "</head>\n<body onload=\"document.forms[0].elements[0].focus();\">\n";
			print "<form action=\"$setpage\" method=\"POST\" style=\"text-align: center; margin-top: 15px;\">\n";
			print "Password: <input type=\"password\" name=\"passwd\">\n";
			print "<input type=\"submit\" value=\"Login\">\n</form>\n";
			mainFooter();
		}
		elsif ($passwd eq crypt($AdminPass, $passwd)) {
			($COOKIE{'P'}) || login_time(1);
			admin_page($passwd, \%COOKIE);
		}
		else {
			error("401 Unauthorized", 3);
		}
	}
	$name = str_cut($name);

	# ディレクトリチェック
	if ($FileDir && -e $FileDir && -d $FileDir) {
		my $file;
		opendir(DIR, $FileDir) || die $!;
		while ($file = readdir(DIR)) {
			if ($file =~ /^(?:\.|index\.html$)/) {
				next;
			}
			elsif ($file eq $name) {
				last;
			}
		}
		closedir(DIR);
		($name && $name eq $file) || error("404 Not Found", 1, $name);
	}
	else {
		error("404 Not Found", 2, "File Directory");
	}

	return $name;
}

#======================================================
#	カウントチェック
#======================================================
sub count_check {
	my($request, $urlmode) = @_;

	# クッキーのパス（ほとんどのサーバは QUERY_STRING 以外に PATH_INFO も REQUEST_URI に付くからカットする）
	$setpage =~ s/$ENV{'PATH_INFO'}$// if ($urlmode && ($ENV{'PATH_INFO'}));
	(my $path = $setpage) =~ s/index\.cgi$//;
	$path =~ s/[^\/]*$// if ($SetPage);

	# ダウンロードカウント
	my $dlcount = $query->cookie(-name=>"dlcount");
	$dlcount =~ tr/0-9//cd;
	$dlcount =~ s/^0*//;
	$dlcount++;
	my $dl_cookie = $query->cookie(-name=>"dlcount", -value=>$dlcount, -path=>$path, -expires=>"+6M");

	# ダウンロードの上限チェック
	my $remain_cookie;
	if ($DownloadLimit) {
		# クッキー受け入れチェック（カウントが2回目以降はパス）
		if ($NeedCookie && $dlcount == 1) {
			my $enable = 'enabledcookie';
			unless ($query->cookie(-name=>$enable)) {
				unless ($query->param('c')) {
					my $accept_cookie = $query->cookie(-name=>$enable, -value=>1, -path=>$path);

					# リダイレクト時に &amp; を解釈しない場合があるから ; か & のみで区切る
					my $uri = "$setpage?c=1&" . (($urlmode) ? "url=" : "name=") . $request;

					# リクエストされた状態をリダイレクトしてクッキー発行
					redirectHeader($accept_cookie, $uri);
				}
				error("403 Forbidden", 4, "Cookie Blocked");
			}
		}

		my $remain = $query->cookie(-name=>"remain");
		$remain =~ tr/0-9//cd;
		$remain = $DownloadLimit if ($remain eq "");
		(--$remain < 0) && error("403 Forbidden", 5, "Download Limit");
		$remain_cookie = $query->cookie(-name=>"remain", -value=>$remain, -path=>$path, -expires=>"+1d");
	}

	return($dlcount, [$dl_cookie, $remain_cookie]);
}

#======================================================
#	制限チェック
#======================================================
sub restrict_check {
	# 参照元チェック
	if ($SetReferer && $SetReferer =~ /^http/) {
		my $referer = $query->referer;
		($referer) || error("403 Forbidden", 0, "Referer Empty");
		$referer =~ s/index\..{3,5}$//;
		$referer =~ s/%7[Ee]/~/g;

		$SetReferer =~ s/index\..{3,5}$//;
		$SetReferer =~ s/%7[Ee]/~/g;

		($referer =~ /^$SetReferer/) || error("403 Forbidden", 7, "Referer");
	}

	# 連続ダウンロードチェック（チェックと更新を一度にするためダウンロード直前に行う）
	if ($WaitTime && $DenyIPFile) {
		# ダウンロード対象の IP アドレスと時間を取得
		my $nowtime = time;
		my(@data) = "$ipaddr,$nowtime\n";

		if (-e $DenyIPFile) {
			my $remaintime;
			per_666($DenyIPFile);
			open(IN, $DenyIPFile) || warn $!;
			eval { flock(IN, 1); };
			while (<IN>) {
				chomp;
				my($addr, $time) = split(/,/);
				my $readytime = $time + $WaitTime;

				# 指定時間内のリストを取得
				if ($nowtime <= $readytime) {
					push(@data, "$_\n");

					# IP アドレスがあれば残り時間をエラーログに渡す
					if ($ipaddr eq $addr) {
						$remaintime = $readytime - $nowtime || 1;
						last;
					}
				}
			}
			close(IN);

			# リストの更新をすると再度ここからの待ち時間になるからここで終了
			if ($remaintime) {
				per_600($DenyIPFile);
				error("403 Forbidden", 6, "Remain $remaintime sec");
			}
		}

		# リストの更新
		open(OUT, "> $DenyIPFile") || warn $!;
		eval { flock(OUT, 2); };
		print OUT @data;
		close(OUT);
		per_600($DenyIPFile);
	}
}

#======================================================
#	ダウンロード
#======================================================
sub download_file {
	my $filename = shift;

	my($mimetype, $code, $buffer);
	while (my($ext, $mime) = each(%MIMETYPE)) {
		next unless ($ext && $filename =~ /$ext$/i);
		$mimetype = $mime; last;
	}
	($mimetype) || error("415 Unsupported Media Type", 1, $filename);

	my($dlcount, $cookie) = count_check($filename);
	my $dl_file = "$FileDir$filename";
	my $size = -s $dl_file;

	# 最終チェック
	restrict_check();
	(-f $dl_file && -r $dl_file) || error("403 Forbidden", 1, $filename);

	# テキストファイルの改行コード変換
	if ($LineFeedChange) {
		# クライアント OS の改行コード判別（UA が不明の場合は変換なし）
		if (-T $dl_file || $mimetype eq "text/plain") {
			my $ua = $query->user_agent;
			if ($ua =~ /Win/) {
				$code = "\x0D\x0A";
			}
			elsif ($ua =~ /Mac|PPC/) {
				unless ($ua =~ /OS X/) {
					$code = "\x0D";
					if ($ua =~ /MSIE (\d\.\d+)/) {
						# IE 5.2x 以降は OS X として除外
						undef($code) if ($1 >= 5.2);
						$mimetype = "octet-stream";
					}
				}
			}
		}
	}

	# バイナリファイル、改行コード変換なしのテキストファイル
	unless ($code) {
		downloadHeader($cookie, $mimetype, $filename, $size);
		open(FILE, $dl_file) || die $!;
		binmode(FILE);
		print $buffer while (read(FILE, $buffer, 4096));
		close(FILE);
	}
	# 改行コード変換時のテキストファイル
	else {
		# 変換する改行コードによってファイルサイズが変わるから一度展開する
		# 通常テキストファイルの改行コードは読み込み時に LF に変換される
		open(FILE, $dl_file) || error("503 Service Unavailable", 2, "Line Feed Failed");
		read(FILE, $buffer, $size);
		close(FILE);

		# 改行コード変換（\x0D はサーバ OS が Windows で読み込み時に CR のみが LF に変換されない場合の対処）
		$buffer =~ s/\x0D|\x0A/$code/g;

		# 変換後のサイズを設定する（ファイルの尻切れ防止とダウンロード状況のプログレスバー表示用）
		downloadHeader($cookie, $mimetype, $filename, length($buffer));
		print $buffer;
		undef($buffer);
	}

	return $dlcount;
}

#======================================================
#	ログファイル書き込み
#======================================================
sub logging {
	my($logname, $code, $count, $extend) = @_;

	# 日時取得
	my($sec, $min, $hour, $mday, $mon, $year, $wday) = (localtime(time))[0..6];
	$year += 1900; $mon++;
	my $date = sprintf("%04d/%02d/%02d", $year, $mon, $mday);
	my $week = ("Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat")[$wday];
	my $time = sprintf("%02d:%02d:%02d", $hour, $min, $sec);

	# ログファイル分割
	my $CURRENTLOG = "$LogDir$logname";
	per_666($CURRENTLOG);
	if (-e $CURRENTLOG) {
		my $timestamp;
		unless ($LogSplitMode) {
			$timestamp = sprintf("%04d%02d%02d%02d%02d", $year, $mon, $mday, $hour, $min) if ($LogSplitSize < -s $CURRENTLOG);
		}
		else {
			my($modmin, $modhour, $modday, $modmon, $modyear) = (localtime((stat($CURRENTLOG))[9]))[1..5];
			$modyear += 1900; $modmon++;
			$timestamp = ($LogSplitMode == 1) ? ($year != $modyear || $mon != $modmon || $mday != $modday) : (($LogSplitMode == 2) && ($year != $modyear || $mon != $modmon));
			$timestamp &&= sprintf("%04d%02d%02d%02d%02d", $modyear, $modmon, $modday, $modhour, $modmin);
		}

		# リネーム処理
		if ($timestamp) {
			$logname =~ s/^\.\///;
			rename($CURRENTLOG, "$LogDir$timestamp$logname") || die $!;

			# 過去ログを全て保存しない場合
			if ($LogSave) {
				# 対象は書き込みログの過去ログ
				opendir(DIR, $LogDir) || die $!;
				my(@list) = sort { $a <=> $b } grep(/^\d{12}$logname$/, readdir(DIR));
				closedir(DIR);

				# 規定数に達していたら一番古いログを削除
				if ($LogSave < scalar(@list)) {
					per_666("$LogDir$list[0]");
					($AdminMailto && $AdminMailto =~ /^[-\.\w]+\@[-\.\w]+\.[-\.\w]+$/ &&
						$SendmailPath && -e $SendmailPath && -x $SendmailPath) && send_log($list[0]);
					unlink("$LogDir$list[0]") || die $!;
				}
			}
		}
	}

	# ファイルのエイリアス
	if (exists($AliasFileName{$code})) {
		$code = $AliasFileName{$code} if ($AliasFileName{$code} =~ /^[-\.\w]+$/);
	}

	# 参照元取得
	my $referer = $query->referer;
	$referer = ($referer) ? str_escape($referer) : "-";

	# ホスト名取得
	my $host = gethostbyaddr(pack("C4", split(/\./, $ipaddr)), 2) || $ipaddr;

	# UA 取得
	my $ua = $query->user_agent;
	$ua = ($ua) ? str_escape($ua) : "-";

	# 拡張データ
	$extend ||= "-";

	# ログ書き込み
	open(OUT, ">> $CURRENTLOG") || warn $!;
	eval { flock(OUT, 2); };
	print OUT "$date,$week,$time,$code,$referer,$host,$ua,$count,$extend,-\n";
	close(OUT);
	per_600($CURRENTLOG);

	# 総ダウンロード数
	if ($TotalCountFile && $count ne "-") {
		my(%downloadList);
		# 今までのダウンロード数取得
		if (-e $TotalCountFile) {
			per_666($TotalCountFile);
			open(IN, $TotalCountFile) || warn $!;
			eval { flock(IN, 1); };
			while (<IN>) {
				chomp;
				my($file, $dlcount, $firstdate, $lastdate) = split(/,/);
				$downloadList{$file} = [$dlcount, $firstdate, $lastdate];
			}
			close(IN);
		}

		# 今回のファイルを追加
		$downloadList{$code}->[0]++;
		$downloadList{$code}->[1] = $date unless ($downloadList{$code}->[1]);
		$downloadList{$code}->[2] = $date;

		# 総ダウンロード数の更新
		open(OUT, "> $TotalCountFile") || warn $!;
		eval { flock(OUT, 2); };
		while (my($name, $value) = each(%downloadList)) {
			print OUT "$name,$value->[0],$value->[1],$value->[2]\n";
		}
		close(OUT);
		per_600($TotalCountFile);
	}
}

#======================================================
#	HTTP ヘッダ
#======================================================
sub downloadHeader {
	my($cookie, $mimetype, $filename, $size) = @_;

	# CGI.pm が古い場合は -attachment, -p3p の形式は使えないから -Content_length と同様に独自のヘッダ引数として扱う
	print $query->header(-cookie=>$cookie, -type=>"application/$mimetype", -Content_disposition=>"attachment; filename=\"$filename\"", -Content_length=>$size, -P3P=>$P3P);
}
sub redirectHeader {
	my($cookie, $url) = @_;

	print $query->redirect(-cookie=>$cookie, -url=>$url, -P3P=>$P3P);
	exit;
}
sub mainHeader {
	print $query->header(-type=>"text/html", -charset=>"UTF-8", -pragma=>"no-cache", -Cache_control=>"no-cache", -expires=>"now");
}
sub adminHeader {
	my(%COOKIE);
	($COOKIE{'P'}, $COOKIE{'L'}, $COOKIE{'D'}, $COOKIE{'V'}, $COOKIE{'DATE'}, $COOKIE{'FILE'}) = @_;

	(my $path = $setpage) =~ s/index\.cgi$//;
	my $exp = ($COOKIE{'P'}) ? "" : "-1d";
	my $cookie = $query->cookie(-name=>$SessionName, -value=>\%COOKIE, -path=>$path, -expires=>$exp);
	unless ($exp) {
		print $query->header(-cookie=>$cookie, -type=>"text/html", -charset=>"UTF-8", -expires=>"now");
	}
	else {
		print $query->redirect(-cookie=>$cookie, -url=>$setpage);
		exit;
	}
}

#======================================================
#	HTML ヘッダ
#======================================================
sub mainHTML {
	my $title = shift || "Download Analysis";
	my $jsflag = shift;

	my $StyleBgColor = $down_cfg::StyleBgColor;
	my $StyleColor = $down_cfg::StyleColor;
	my $StyleFont = $down_cfg::StyleFont;
	my $StyleSize = $down_cfg::StyleSize;
	my $StyleBorder = $down_cfg::StyleBorder;
	my $StyleHeader = $down_cfg::StyleHeader;
	my $StyleGraph = $down_cfg::StyleGraph;
	my $StyleGraphBdr = $down_cfg::StyleGraphBdr . "px";
	my $StyleGraphBdrColor = $down_cfg::StyleGraphBdrColor;
	my $StyleLink = $down_cfg::StyleLink;
	my $StyleVlink = $down_cfg::StyleVlink;

	print <<EOF;
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html lang="ja">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<meta http-equiv="Content-Script-Type" content="text/javascript">
<meta http-equiv="Content-Style-Type" content="text/css">
<title>$title</title>
<style type="text/css">
<!--
body, input, select {
	background-color: $StyleBgColor;
	color: $StyleColor;
	font-size: $StyleSize;
	font-family: $StyleFont;
}
fieldset {
	border: 1px solid $StyleBorder;
	margin-top: 5px;
	padding: 3px;
}
input, select {
	border: 1px solid $StyleBorder;
	font-size: 100%;
}
table {
	background-color: $StyleBorder;
	font-size: 100%;
}
caption, th, td {
	text-align: left;
	white-space: nowrap;
}
tr {
	background-color: $StyleBgColor;
}
th {
	background-color: $StyleHeader;
	font-weight: normal;
}
td div {
	background-color: $StyleGraph;
	border: $StyleGraphBdr solid $StyleGraphBdrColor;
	font-style: italic;
	text-align: center;
}
table#config th {
	background-color: $StyleBgColor;
	padding-left: 15px;
}
dd {
	margin-left: 15px;
}
a {
	color: $StyleLink;
	text-decoration: none;
}
a:hover {
	color: #ff00ff;
	text-decoration: underline;
}
a.outer:visited {
	color: $StyleVlink;
}
.bo {
	font-weight: bold;
}
.r {
	text-align: right;
}
.red {
	color: #ff0000;
}
div#footer {
	border-top: 1px solid $StyleBorder;
	margin-top: 15px;
	padding: 2px 0 5px 0;
}
-->
</style>
EOF

	if ($jsflag) {
		print <<EOF;
<script type="text/javascript">
<!--
window.onload = function() {
	var obj = document.forms[0];
	obj.mode.options[0].selected = true;
	if (window.opera && obj.mode.options[1].value != "delete") {
		var opt = document.createElement("option");
		opt.value = "delete";
		opt.text = "Delete";
		obj.mode.children[1].insertAdjacentElement("beforeBegin", opt);
	}

	for (var i = 0; i < document.links.length - 1; i++) {
		var ele = document.links[i];
		if (ele.className == "outer") {
			ele.onclick = openwin;
			var anc = ele.href;
			if (anc.length > 45) ele.title = (anc.length > 70) ? anc.substr(0, 65) + "..." : anc;
		}
	}
}
function openwin() {
	var url = this.href;
	if (document.all && !window.opera && url.match(/[^\\x21-\\x7E]/)) {
		if (!window.createPopup) {
			this.target = "_blank";
			return true;
		}
		url = escape(url);
		url = decodeURIComponent(url);
		url = encodeURI(url);
	}
	window.open(url);
	return false;
}
function verify() {
	var obj = document.forms[0];
	obj.mode.blur();
	if (obj.mode.value == "delete" && !confirm(obj.logname.value + "\\nを削除してもよろしいですか？")) {
		obj.mode.options[0].selected = true;
		return;
	}
	obj.submit();
}
// -->
</script>
EOF

	}

}

#======================================================
#	フッタ
#======================================================
sub mainFooter {
	my $flag = shift;

	print "<!-- ここから変更しないでください -->\n";
	print "<div id=\"footer\">\n";
	print "<div style=\"width: 50%; float: left;\">";
	if ($flag) {
		# ログイン時間表示
		if ($flag == 1) {
			login_time();
		}
		# 解析表示に戻るリンク
		elsif ($flag == 2) {
			print "<a href=\"$setpage\">[BACK]</a>";
		}
		# エラー時に前のページに戻るリンク
		else {
			my $referer = $query->referer;
			my $back = ($referer && $referer =~ /^http/) ? str_escape($referer) : "javascript:history.back();";
			print "<a href=\"$back\">[BACK]</a>";
		}
	}
	print "<!-- " . times . " --></div>\n<address class=\"r\">- ";
	print "<a href=\"http://www9.plala.or.jp/oyoyon/\" class=\"outer\" title=\"Download Analysis $Version\">Presented by oyoyon</a>";
	print " -</address>\n</div>\n";
	print "<!-- ここまで -->\n";
	print "</body>\n</html>";
	exit;
}

#======================================================
#	総ダウンロード数
#======================================================
sub total_downloads {
	print "</head>\n<body>\n";

	if ($TotalCountFile && -e $TotalCountFile) {
		my(@date, %downloadList, $total, $count, $adjust, $value);
		per_666($TotalCountFile);
		open(IN, $TotalCountFile) || die $!;
		eval { flock(IN, 1); };
		while (<IN>) {
			chomp;
			my($file, $dlcount, $firstdate, $lastdate) = split(/,/);

			push(@date, $firstdate, $lastdate);
			$downloadList{$file} = [$dlcount, $firstdate, $lastdate];
			$total += $dlcount;
		}
		close(IN);
		per_600($TotalCountFile);

		my $period = join(" - ", (sort @date)[0,-1]);
		print "<table cellpadding=\"3\" cellspacing=\"1\">\n";
		print "<caption>Total Download Count [Downloaded $total Times] ($period)</caption>\n";
		print "<tr>\n";
		print "<th>＼</th>\n";
		print "<th>File Name</th>\n";
		print "<th>Total Count</th>\n";
		print "<th width=\"50%\">Graph (Rate)</th>\n";
		print "<th>Period</th>\n";
		print "</tr>\n";

		foreach (sort { $downloadList{$b}->[0] <=> $downloadList{$a}->[0] || $a cmp $b } keys %downloadList) {
			$adjust = ($downloadList{$_}->[0] == $value) ? ++$adjust : 0;
			$value = $downloadList{$_}->[0];
			my $per = sprintf("%.1f%%", ($value / $total) * 100);

			my $startsec = time_seconds($downloadList{$_}->[1]);
			my $endsec = time_seconds($downloadList{$_}->[2]);
			my $days = int(($endsec - $startsec) / 86400);

			print "<tr>\n";
			printf("<td>%03d</td>\n", ++$count - $adjust);
			print "<td>$_</td>\n";
			print "<td class=\"r\">$value</td>\n";
			print "<td><div style=\"width: $per;\">$per</div></td>\n";
			print "<td>$downloadList{$_}->[1] - $downloadList{$_}->[2] ($days days)</td>\n";
			print "</tr>\n";
		}
		print "</table>\n";
	}
	else {
		print "<p>Total download file is not found.</p>\n";
	}
}

#======================================================
#	管理画面
#======================================================
sub admin_page {
	my($passwd, $COOKIE) = @_;

	# ログファイル名の取得とチェック
	my $logname = $query->param('logname') || $COOKIE->{'L'} || $DownLog;
	$logname = str_cut($logname);
	($logname =~ /^(?:\d{12})?(?:$DownLog|$ErrLog)$/) || adminHeader();
	my $CURRENTLOG = "$LogDir$logname";

	# モード取得、フッタの判別（該当ログがない場合はファイル情報表示）
	my($mode, $myfooter) = (-e $CURRENTLOG) ? (str_cut($query->param('mode')), 2) : ("info", 1);

	# パーミッションチェック
	($mode =~ /^(?:logout|info|total)$/) || per_666($CURRENTLOG);

	# ログダウンロード
	if ($mode eq "download") {
		my $mime = ($logname =~ /\.csv$/i) ? "application/x-csv" : "application/text/plain";
		my $size = -s $CURRENTLOG;

		print $query->header(-type=>$mime, -Content_disposition=>"attachment; filename=\"$logname\"", -Content_length=>$size);
		open(FILE, $CURRENTLOG) || die $!;
		eval { flock(FILE, 1); };
		binmode(FILE);
		print <FILE>;
		close(FILE);
		per_600($CURRENTLOG);
		exit;
	}
	# ログ削除
	elsif ($mode eq "delete") {
		unlink($CURRENTLOG) || die $!;

		adminHeader($passwd);
		mainHTML();
		print "</head>\n<body>\n";
		print "<p class=\"red\">$logname was deleted.</p>\n";
		mainFooter(2);
	}
	# ログアウト
	elsif ($mode eq "logout") {
		adminHeader();
	}
	# ファイル情報＋簡易チェック
	elsif ($mode eq "info") {
		my($filedir_state, $logdir_state, $logdir_size, %scriptFiles, $same_name);
		my $myhost = (($ENV{'HTTPS'}) ? "https://" : "http://") . ($ENV{'HTTP_HOST'} || $ENV{'SERVER_NAME'});

		# ヘッダ出力
		adminHeader($passwd, $logname, $COOKIE->{'D'}, $COOKIE->{'V'}, $COOKIE->{'DATE'}, $COOKIE->{'FILE'});
		mainHTML();
		print "</head>\n<body>\n";

		# ファイルディレクトリ一覧＋チェック
		if ($FileDir && -e $FileDir && -d $FileDir && -r $FileDir && -x $FileDir) {
			print "<table width=\"100%\" cellpadding=\"3\" cellspacing=\"1\">\n";
			print "<tr>\n";
			print "<th>File Name</th>\n";
			print "<th>Last Modified</th>\n";
			print "<th>Size (Bytes)</th>\n";
			print "<th>URL (Link of download)</th>\n";
			print "</tr>\n";

			my($byte, $cnt) = (0, 0);
			opendir(DIR, $FileDir) || die $!;
			foreach (sort readdir(DIR)) {
				next if (/^(?:\.|index\.html$)/);
				my($file, $size, $link) = "$FileDir$_";
				my($mday, $mon, $year) = (localtime((stat($file))[9]))[3..5];
				if (-f $file) {
					$byte += $size = -s $file;
					foreach my $ext (keys %MIMETYPE) {
						if (/$ext$/i) {
							$link = "$myhost$setpage?name=$_"; last;
						}
					}
					$link = "-" unless ($link && /^[-\.\w]+$/);
				}
				else {
					$size = "-";
					$link = "N/A";	
				}
				$cnt++;

				print "<tr>\n";
				print "<td>$_</td>\n";
				printf("<td>%04d/%02d/%02d</td>\n", $year + 1900, $mon + 1, $mday);
				print "<td class=\"r\">" . number_split($size) . "</td>\n";
				print "<td>$link</td>\n";
				print "</tr>\n";
			}
			closedir(DIR);

			print "<caption>Saved File [$cnt File " . higher_byte($byte) . "]</caption>\n";
			print "</table>\n";

			# カレントディレクトリのパス取得
			(my $mypath = $setpage) =~ s/[^\/]*$//;

			# 相対パス (./ ../) をカット
			(my $dir = $FileDir) =~ s/^\.\///;
			if ($FileDir =~ /^\.\.\//) {
				my $i = $dir =~ s/\.\.\///g;
				$mypath =~ s/[^\/]*\/$// while ($i--);	# $mypath =~ s/(?:[^\/]*\/){$i}$//;
			}
			$filedir_state = $FileDir . (($FileDir =~ /^[^\/][-\.\/\w]+\/$/) ? " (" .
				(($mypath) ? "$myhost$mypath$dir" : "Not detected.") . ") [OK]" : " [NG]");
		}
		else {
			print "<p>Can't find file directory or is not permission.</p>\n";
			$filedir_state = "<span class=\"red\">[NG]</span>";
		}

		# ログディレクトリチェック
		if ($LogDir && -e $LogDir && -d $LogDir && -r $LogDir && -w $LogDir && -x $LogDir) {
			(my $dir = $LogDir) =~ s/^\.\///;
			(my $mypath = $setpage) =~ s/[^\/]*$//;
			if ($LogDir =~ /^\.\.\//) {
				my $i = $dir =~ s/\.\.\///g;
				$mypath =~ s/[^\/]*\/$// while ($i--);
			}
			$logdir_state = $LogDir . (($LogDir =~ /^[^\/][-\.\/\w]+\/$/) ? " (" .
				(($mypath) ? "$myhost$mypath$dir" : "Not detected.") . ") [OK]" : " [NG]");

			# ログの総サイズ
			opendir(DIR, $LogDir) || die $!;
			while (my $file = readdir(DIR)) {
				next if ($file =~ /^(?:\.|index\.html$)/);
				$logdir_size += -s "$LogDir$file";
			}
			closedir(DIR);
		}
		else {
			$logdir_state = "<span class=\"red\">[NG - Can't find log directory or is not permission.]</span>";
		}

		# 重複ファイル名チェック
		my $cgifile = $query->url(-relative=>1);
		foreach (".", "..", "index.html", $cgifile, $cfg_file, $DownLog, $ErrLog, $TotalCountFile, $LoginLogFile, $DenyIPFile) {
			next unless ($_);
			(my $name = $_) =~ s/^\.\///;
			$name =~ tr/A-Z/a-z/;
			if (++$scriptFiles{$name} > 1) {
				$same_name = str_escape($_); last;
			}
		}

		# 簡易チェック
		my $downlog_state = ($DownLog && $DownLog ne $same_name && $DownLog =~ /^([-\.\w]+)$/) ? ((-e "$LogDir$DownLog" && -f "$LogDir$DownLog") ? "$1 [OK - Exist]" : "$1 [OK]") : "[NG]";
		my $errlog_state = ($ErrLog && $ErrLog ne $same_name && $ErrLog =~ /^([-\.\w]+)$/) ? ((-e "$LogDir$ErrLog" && -f "$LogDir$ErrLog") ? "$1 [OK - Exist]" : "$1 [OK]") : "[NG]";
		my $split_state = ($LogSplitMode) ?
			(($LogSplitMode == 1) ? "Every day [OK]" : (($LogSplitMode == 2) ? "Every month [OK]" : "Not Split [NG]")) :
			(($LogSplitSize && $LogSplitSize =~ /^\d+$/) ? "Size: " . higher_byte($LogSplitSize) . " [OK]" : "Size [NG]");
		my $save_state = ($LogSave) ? (($LogSave =~ /^\d+$/) ? "Up to $LogSave [OK]": "[NG]") : "ALL [OK]";
		my $send_state = ($LogSave) ? (($AdminMailto || $SendmailPath) ?
			(($AdminMailto =~ /^[-\.\w]+\@[-\.\w]+\.[-\.\w]+$/ && -e $SendmailPath && -x $SendmailPath) ?
			"$AdminMailto [OK]" : "[NG]") : "Disabled [OK]") : "Not Available [OK]";
		my $totalfile_state = ($TotalCountFile) ? (($TotalCountFile ne $same_name && $TotalCountFile =~ /^(?:\.\/)?([-\.\w]+)$/) ?
			((-e $TotalCountFile && -f $TotalCountFile) ? "$1 [OK - Exist]" : "$1 [OK]") : "[NG]") : "Disabled [OK]";
		my $login_state = ($LoginLogFile) ? (($LoginLogFile ne $same_name && $LoginLogFile =~ /^(?:\.\/)?([-\.\w]+)$/) ?
			((-e $LoginLogFile && -f $LoginLogFile) ? "$1 [OK - Exist]" : "$1 [OK]") : "[NG]") : "Disabled [OK]";
		my $number_state = ($RowIndexFormat) ? "Ranking" : "Sequential";
		my $public_state = ($TotalCountFile && $ViewTotalCount) ? "Everyone" : "Administrator Only";
		my $crlf_state = ($LineFeedChange) ? "Enabled" : "Disabled";
		my $url_state = ($UrlDirectory) ? (($UrlDirectory =~ /^https?:\/\/[!\$%&'\(\)\*\+,\-\.\/\w:;=\?\@~]+\/$/) ? "$& [OK]" : "[NG]") : "Disabled [OK]";
		my $ref_state = ($SetReferer) ? (($SetReferer =~ /^https?:\/\/[!\$%&'\(\)\*\+,\-\.\/\w:;=\?\@~]+$/) ? "$& [OK]" : "[NG]") : "Disabled [OK]";
		my $limit_state = ($DownloadLimit) ? (($DownloadLimit =~ /^\d+$/) ? "$DownloadLimit File / Day (1 Client) [OK]": "[NG]") : "Disabled [OK]";
		my $cookie_state = ($DownloadLimit && $NeedCookie) ? "Enabled" : "Disabled";
		my $downip_state = ($WaitTime && $DenyIPFile) ?
			(($WaitTime =~ /^\d+$/ && $DenyIPFile ne $same_name && $DenyIPFile =~ /^(?:\.\/)?([-\.\w]+)$/) ?
			"$WaitTime sec ($1) " . ((-e $DenyIPFile && -f $DenyIPFile) ? "[OK - Exist]" : "[OK]") : "[NG]") : "Disabled [OK]";
		my $errorcode_state = (($UnRecErrorCode) &&
			$UnRecErrorCode =~ /^([0-7]{1,8}|0\-[1-7]|1\-[2-7]|2\-[3-7]|3\-[4-7]|4\-[567]|5\-[67]|6\-7)$/) ?
			"Except Code of " . (($1 =~ /^[0-7]{1,8}$/) ? join(", ", split(//, $UnRecErrorCode)) : $UnRecErrorCode) . " [OK]" :
			(($UnRecErrorCode eq "") ? "ALL [OK]" : "[NG]");

		# 設定ファイル最終更新日
		my($min, $hour, $mday, $mon, $year) = (localtime((stat($cfg_file))[9]))[1..5];
		my $mtime = sprintf("%04d/%02d/%02d %02d:%02d", $year + 1900, $mon + 1, $mday, $hour, $min);

		# 設定情報
		print "<p class=\"red\">Warning: This file name overlaps. ($same_name)</p>" if ($same_name);
		print "<fieldset>\n<legend class=\"red\">Config Information</legend>\n";
		print "<table cellpadding=\"3\" cellspacing=\"0\" id=\"config\">\n";
		print "<tr>\n";
		print "<td colspan=\"2\" class=\"bo\">General</td>\n";
		print "</tr>\n";
		print "<tr>\n";
		print "<th>File Directory</th>\n";
		print "<td>$filedir_state</td>\n";
		print "</tr>\n";
		print "<tr>\n";
		print "<th>Log Directory</th>\n";
		print "<td>$logdir_state</td>\n";
		print "</tr>\n";
		print "<tr>\n";
		print "<th>Download Log</th>\n";
		print "<td>$downlog_state</td>\n";
		print "</tr>\n";
		print "<tr>\n";
		print "<th>Error Log</th>\n";
		print "<td>$errlog_state</td>\n";
		print "</tr>\n";
		print "<tr>\n";
		print "<th>Log Split</th>\n";
		print "<td>$split_state</td>\n";
		print "</tr>\n";
		print "<tr>\n";
		print "<th>Past Log Save</th>\n";
		print "<td>$save_state</td>\n";
		print "</tr>\n";
		print "<tr>\n";
		print "<th>Past Log Send</th>\n";
		print "<td>$send_state</td>\n";
		print "</tr>\n";
		print "<tr>\n";
		print "<th>Total Count File</th>\n";
		print "<td>$totalfile_state</td>\n";
		print "</tr>\n";
		print "<tr>\n";
		print "<th>Login Record File</th>\n";
		print "<td>$login_state</td>\n";
		print "</tr>\n";
		print "<tr>\n";
		print "<th>Number Display Format</th>\n";
		print "<td>$number_state [OK]</td>\n";
		print "</tr>\n";
		print "<tr>\n";
		print "<td colspan=\"2\" class=\"bo\">Options</td>\n";
		print "</tr>\n";
		print "<tr>\n";
		print "<th valign=\"top\">Allow Login Domain</th>\n";
		if (@AllowLoginDomain) {
			my($count, $cnt) = scalar(@AllowLoginDomain);
			print "<td>";
			foreach (sort @AllowLoginDomain) {
				next unless (/^[\*\-\.\w]+$/);
				print $_ . ((++$cnt % 5 == 0 && $cnt != $count) ? "<br>" : " ");
			}
			print(($cnt == $count) ? "[OK]" : "[NG]");
			print "</td>\n";
		}
		else {
			print "<td>Disabled [OK]</td>\n";
		}
		print "</tr>\n";
		print "<tr>\n";
		print "<th>Total Count Display</th>\n";
		print "<td>$public_state [OK]</td>\n";
		print "</tr>\n";
		print "<tr>\n";
		print "<th>Line Feed Change</th>\n";
		print "<td>$crlf_state [OK]</td>\n";
		print "</tr>\n";
		print "<tr>\n";
		print "<th>URL Mode</th>\n";
		print "<td>$url_state</td>\n";
		print "</tr>\n";
		if ($UrlDirectory && @UrlFileList) {
			my($count, $cnt) = scalar(@UrlFileList);
			print "<tr>\n";
			print "<th valign=\"top\">URL Mode File List</th>\n";
			print "<td>";
			foreach (sort @UrlFileList) {
				next unless (/^[-\.\w]+$/);
				print $_ . ((++$cnt % 5 == 0 && $cnt != $count) ? "<br>" : " ");
			}
			print(($cnt == $count) ? "[OK - $count File]" : "[NG - $cnt / $count]");
			print "</td>\n";
			print "</tr>\n";
		}
		print "<tr>\n";
		print "<th valign=\"top\">Alias File Name</th>\n";
		if (%AliasFileName) {
			my($count, $cnt) = scalar(keys(%AliasFileName));
			print "<td>";
			foreach (sort { $AliasFileName{$a} cmp $AliasFileName{$b} } keys %AliasFileName) {
				next unless (/^[-\.\w]+\.[0-9A-Za-z]+$/ && $AliasFileName{$_} =~ /^[-\.\w]+$/);
				print "$_ -&gt; $AliasFileName{$_}" . ((++$cnt != $count) ? "<br>" : " ");
			}
			print(($cnt == $count) ? "[OK]" : "[NG - $cnt / $count]");
			print "</td>\n";
		}
		else {
			print "<td>None [OK]</td>\n";
		}
		print "</tr>\n";
		print "<tr>\n";
		print "<th valign=\"top\">Additional MIME Type</th>\n";
		if (%AddMime) {
			my($count, $cnt) = scalar(keys(%AddMime));
			print "<td>";
			foreach (sort { $AddMime{$a} cmp $AddMime{$b} } keys %AddMime) {
				next unless (/^\\?\.[\(\)\*\+\-\.\w\?\[\\\]\|]+$/ && $AddMime{$_} =~ /^(?!application\/)[-\.\/\w]+$/);
				print $AddMime{$_} . ((++$cnt % 5 == 0 && $cnt != $count) ? "<br>" : " ");
			}
			print(($cnt == $count) ? "[OK]" : "[NG - $cnt / $count]");
			print "</td>\n";
		}
		else {
			print "<td>None [OK]</td>\n";
		}
		print "</tr>\n";
		print "<tr>\n";
		print "<td colspan=\"2\" class=\"bo\">Limit</td>\n";
		print "</tr>\n";
		print "<tr>\n";
		print "<th>Set Referer</th>\n";
		print "<td>$ref_state</td>\n";
		print "</tr>\n";
		print "<tr>\n";
		print "<th>Download Limit</th>\n";
		print "<td>$limit_state</td>\n";
		print "</tr>\n";
		print "<tr>\n";
		print "<th>Accept Cookie Check</th>\n";
		print "<td>$cookie_state [OK]</td>\n";
		print "</tr>\n";
		print "<tr>\n";
		print "<th>Download Interval</th>\n";
		print "<td>$downip_state</td>\n";
		print "</tr>\n";
		print "<tr>\n";
		print "<td colspan=\"2\" class=\"bo\">Advanced</td>\n";
		print "</tr>\n";
		print "<tr>\n";
		print "<th>Error Record</th>\n";
		print "<td>$errorcode_state</td>\n";
		print "</tr>\n";
		if ($SetPage) {
			print "<tr>\n";
			print "<th>Script Path (Cookie Path)</th>\n";
			print "<td>" . (($SetPage =~ /^\/[!\$%&'\(\)\*\+,\-\.\/\w:;=\?\@~]*/) ? "$SetPage [OK]" : "[NG]") . "</td>\n";
			print "</tr>\n";
		}
		print "<tr>\n";
		print "<td colspan=\"2\" class=\"bo\">Misc</td>\n";
		print "</tr>\n";
		print "<tr>\n";
		print "<th>Log Directory Size</th>\n";
		print "<td>" . higher_byte($logdir_size) . "</td>\n";
		print "</tr>\n";
		print "<tr>\n";
		print "<th>Config Last Modified</th>\n";
		print "<td>$mtime</td>\n";
		print "</tr>\n";
		print "</table>\n";
		print "</fieldset>\n";
		mainFooter($myfooter);
	}
	# 総ダウンロード数
	elsif ($mode eq "total") {
		mainHeader();
		mainHTML();
		total_downloads();
		mainFooter(2);
	}
	# ログ展開
	else {
		my(@logList, @keys, $viewCount, %lastdayList, %dateSelect, %fileSelect, $specifyCount, $specifyPeriod, $pagelink);
		open(IN, $CURRENTLOG) || die $!;
		eval { flock(IN, 1); };
		my $TOTALLOGS = $viewCount = (@logList) = <IN>;
		close(IN);
		per_600($CURRENTLOG);

		# ログサイズ、ログ判別
		my $size = number_split(-s $CURRENTLOG);
		my $dllog_flag = ($logname =~ /$DownLog$/) ? 1 : 0;

		# 開始日時と最終日時
		my $firstDate = join(" ", (split(/,/, $logList[0]))[0,2]);
		my $lastDate = join(" ", (split(/,/, $logList[-1]))[0,2]);

		# 検索（指定表示）キー取得
		my $keyDate = $query->param('keyDate') || $COOKIE->{'DATE'};
		$keyDate =~ tr/\x2F-\x39//cd;
		my $keyFile = $query->param('keyFile') || $COOKIE->{'FILE'};
		$keyFile &&= str_cut($keyFile);
		my $keyHost = $query->param('keyHost');
		$keyHost &&= str_cut($keyHost);

		# 日付、ファイル名、最終ダウンロード日を取得。検索キーがあればそのレコードを取得
		foreach (@logList) {
			chomp;
			my($date, undef, undef, $name, undef, $host, undef, undef, undef, undef) = split(/,/);
			$lastdayList{$name} = $date;
			my $yymm = substr($date, 0, 8);

			if ($keyDate || $keyFile || $keyHost) {
				next if ($keyDate && $keyDate !~ /^(?:$date|$yymm)$/);
				next if ($keyFile && $keyFile ne $name);
				next if ($keyHost && $keyHost ne $host);
				push(@keys, $_);
			}

			$dateSelect{$date}++;
			$dateSelect{$yymm}++;
			$fileSelect{$name}++;
		}

		# 検索キーがあればリスト入れ替え
		if (@keys) {
			undef(@logList);
			$viewCount = @logList = @keys;
			undef(@keys);

			# 表示用キー数
			$specifyCount = $viewCount . " / ";

			# 表示ログの期間
			my $from = join(" ", (split(/,/, $logList[0]))[0,2]);
			my $to = join(" ", (split(/,/, $logList[-1]))[0,2]);
			$specifyPeriod = " ($from - $to)";
		}

		# 表示方法（ソート）
		my $display = $query->param('display') || $COOKIE->{'D'};
		($display eq "up") || undef($display);

		# 1ページ表示件数
		my $ViewPage = $query->param('ViewPage') || $COOKIE->{'V'};
		$ViewPage = 30 unless ($ViewPage && $ViewPage =~ /^\d+$/ && $ViewPage > 0 && $ViewPage <= 100);

		# ページ移動（表示範囲）
		my $page = $query->param('page');
		$page = 0 unless ($page && $page =~ /^\d+$/ && $page > 0 && $page < $viewCount);

		my $nextpage = $ViewPage + $page;
		$nextpage = $viewCount if ($nextpage > $viewCount);

		# ホスト名用検索クエリ（有効なホスト名がある場合）
		my $hosts = "&amp;keyHost=" . url_encode($keyHost) if ($keyHost && $specifyCount);

		# ヘッダ出力
		adminHeader($passwd, $logname, $display, $ViewPage, $keyDate, $keyFile);
		mainHTML("", 1);
		print "</head>\n<body>\n";

		# メインフォーム
		print "<form action=\"$setpage\" method=\"POST\">\n";
		print "<table cellpadding=\"0\" cellspacing=\"0\" id=\"config\">\n";
		print "<tr>\n";
		print "<td>First Access</td>\n";
		print "<td>: $firstDate</td>\n";
		print "<th>Log Count</th>\n";
		print "<td>: $specifyCount$TOTALLOGS</td>\n";
		print "<th>Log Name</th>\n";
		print "<td>: <select name=\"logname\" onchange=\"keyDate.options[0].selected = true;\">\n";
		opendir(DIR, $LogDir) || die $!;
		foreach (sort { $a <=> $b } readdir(DIR)) {
			next unless (/^(?:\d{12})?(?:$DownLog|$ErrLog)$/);
			my $select = " class=\"red\" selected" if ($_ eq $logname);
			print "<option value=\"$_\"$select>$_\n";
		}
		closedir(DIR);
		print "</select></td>\n";
		print "<td><select name=\"ViewPage\" onchange=\"verify();\">\n";
		foreach (10, 30, 50, 100) {
			my $select = " selected" if ($_ == $ViewPage);
			print "<option value=\"$_\"$select>$_ view\n";
		}
		print "</select>\n";
		if ($hosts) {
			print "<input type=\"checkbox\" name=\"keyHost\" value=\"$keyHost\"";
			print " title=\"Host Search\" style=\"border: none;\" checked>\n"
		}
		print "</td>\n";
		if ($dllog_flag) {
			print "<td><select onchange=\"location.hash = this.value; options[0].selected = true; document.body.focus();\">\n";
			print "<option value=\"#\">QUICK JUMP\n";
			print "<option value=\"DATE\">DATE\n" unless ($keyDate =~ /^\d{4}\/\d\d\/\d\d$/);
			print "<option value=\"FILE\">FILE\n";
			print "</select></td>\n";
		}
		print "</tr>\n";
		print "<tr>\n";
		print "<td>Last Access</td>\n";
		print "<td>: $lastDate</td>\n";
		print "<th>Log Size</th>\n";
		print "<td>: $size Bytes</td>\n";
		print "<th>Select Mode</th>\n";
		print "<td>: <select name=\"mode\" onchange=\"verify();\">\n";
		print "<optgroup label=\"Main\">\n";
		print "<option value=\"show\" selected>Show\n";
		print "</optgroup>\n";
		print "<optgroup label=\"File\">\n";
		print "<script type=\"text/javascript\">\n<!--\n\t";
		print "document.write('<option value=\"delete\">Delete');\n// -->\n</script>\n";
		print "<option value=\"download\">Download\n";
		print "</optgroup>\n";
		print "<optgroup label=\"Other\">\n";
		print "<option value=\"total\">Total Count\n" if ($TotalCountFile);
		print "<option value=\"info\">File Info\n";
		print "<option value=\"logout\">Logout\n";
		print "</optgroup>\n";
		print "</select>\n";
		print "<select name=\"keyDate\" onchange=\"verify();\">\n";
		print "<option value=\"#\">ALL DATE\n";
		foreach (sort keys %dateSelect) {
			my $select = " class=\"red\" selected" if ($_ eq $keyDate);
			print "<option value=\"$_\"$select>$_\n";
		}
		print "</select></td>\n";
		if ($dllog_flag) {
			print "<td><select name=\"keyFile\" onchange=\"keyDate.options[0].selected = true;\">\n";
			print "<option value=\"#\">ALL FILE\n";
			foreach (sort keys %fileSelect) {
				my $select = " class=\"red\" selected" if ($_ eq $keyFile);
				print "<option value=\"$_\"$select>$_\n";
			}
			print "</select></td>\n";
		}
		print "<td><input type=\"submit\" value=\"This Change\" onclick=\"verify(); return false;\"></td>\n";
		print "</tr>\n";
		if ($hosts) {
			my $cols = ($dllog_flag) ? 7 : 6;
			print "<tr class=\"red\">\n";
			print "<td>Host Search</td>\n";
			print "<td colspan=\"$cols\">: $keyHost</td>\n";
			print "</tr>\n";
		}
		print "</table></form>\n";

		# ページ切り替えリンク
		if ($page) {
			my $prev = $page - $ViewPage;
			$prev = 0 if ($prev < 0);
			$pagelink .= "<a href=\"$setpage?page=$prev$hosts\">[PREV]</a>&nbsp;";
		}
		my $pv = ($viewCount - 1) / $ViewPage;
		if ($pv >= 1) {
			$pv = int($pv);
			my $now = int($page / $ViewPage) + 1;
			my $vlink = ($pv < 100) ? 5 : 10;

			my($view, $flag);
			for (0..$pv) {
				$view = $_ * $ViewPage;
				$_++;
				if ($_ >= ($now + $vlink)) {
					next unless ($flag);
					my $max = $pv * $ViewPage;
					$pagelink .= "... " if ($now <= ($pv - $vlink));
					$pagelink .= "<a href=\"$setpage?page=$max$hosts\">[" . ($pv + 1) . "]</a>&nbsp;";
					$flag = 0;
				}
				elsif ($_ <= ($now - $vlink)) {
					next if ($flag);
					$pagelink .= "<a href=\"$setpage?page=0$hosts\">[1]</a>&nbsp;";
					$pagelink .= "... " unless ($now <= ($_ + $vlink));
					$flag = 1;
				}
				else {
					$pagelink .= ($_ == $now) ? "<span class=\"bo\">[$_]</span>&nbsp;" :
						"<a href=\"$setpage?page=$view$hosts\">[$_]</a>&nbsp;";
					$flag = 1;
				}
			}
		}
		$pagelink .= "<a href=\"$setpage?page=$nextpage$hosts\">[NEXT]</a>" if ($nextpage < $viewCount);

		# 表題
		my($content, $title, $dl_cnt) = ($dllog_flag) ? ("Download", "File Name", " (Downloads)") : ("Error", "Error Code", "");

		# 表示切り替え、表示方法（昇順、降順）
		my($disp_change, $count);
		if ($display) {
			$disp_change = "down";
			$count = $page + 1;
		}
		else {
			$disp_change = "up";
			$count = $viewCount - $page;
			(@logList) = reverse(@logList);
		}

		# ログ表示
		print "<table cellpadding=\"3\" cellspacing=\"1\">\n";
		print "<caption>$content Log $pagelink$specifyPeriod</caption>\n";
		print "<tr>\n";
		print "<th><a href=\"$setpage?page=$page&amp;display=$disp_change$hosts\">No.</a></th>\n";
		print "<th>Date</th>\n";
		print "<th>Time</th>\n";
		print "<th>$title</th>\n";
		print "<th>Referer</th>\n";
		print "<th>Host Name$dl_cnt</th>\n";
		print "<th>User Agent</th>\n";
		print "</tr>\n";

		my(%dateList, %nameList, $i, $datecount);
		my $show_day = ($keyDate && $keyDate =~ /^\d{4}\/\d\d\/$/);
		foreach (@logList) {
			chomp;
			my($date, $week, $time, $name, $referer, $host, $ua, $dlcount, $extra, undef) = split(/,/);

			$dateList{(($show_day) ? $date : substr($date, 0, 8))}++;
			$nameList{$name}++;
			$i++;

			# 表示範囲以外は無視
			next if ($i <= $page || $i > $nextpage);

			unless ($dllog_flag || $extra eq "-") {
				$name .= (length($extra) > 20) ? " (" . substr($extra, 0, 15) . "...)" : " ($extra)";
			}
			$referer =~ s/%2c/,/g;
			my $url = (length($referer) > 45) ? substr($referer, 0, 40) . "..." : $referer;
			$referer = ($referer =~ /^http/) ? "<a href=\"$referer\" class=\"outer\">$url</a>" : $url;
			$host = "<a href=\"$setpage?keyHost=" . url_encode($host) . "\">$host</a>" unless ($hosts);
			my $downloads = " ($dlcount)" unless ($dlcount eq "-");
			$ua =~ s/%2c/,/g;
			$ua = substr($ua, 0, 50) . "..." if (length($ua) > 55);

			print "<tr>\n";
			printf("<td>%03d</td>\n", (($display) ? $count++ : $count--));
			print "<td>$date ($week)</td>\n";
			print "<td>$time</td>\n";
			print "<td>$name</td>\n";
			print "<td>$referer</td>\n";
			print "<td>$host$downloads</td>\n";
			print "<td>$ua</td>\n";
			print "</tr>\n";
		}

		# 日付表示（検索キーが YYYYMMDD の場合は表示しない）
		unless ($keyDate && $keyDate =~ /^\d{4}\/\d\d\/\d\d$/) {
			print "<tr>\n";
			print "<th>＼</th>\n";
			print "<th colspan=\"2\" id=\"DATE\">Date</th>\n";
			print "<th>Count</th>\n";
			print "<th colspan=\"3\">Graph (Rate)</th>\n";
			print "</tr>\n";

			foreach (sort keys %dateList) {
				my $per = sprintf("%.1f%%", ($dateList{$_} / $TOTALLOGS) * 100);

				print "<tr>\n";
				printf("<td>%03d</td>\n", ++$datecount);
				print "<td colspan=\"2\">$_</td>\n";
				print "<td class=\"r\">$dateList{$_}</td>\n";
				print "<td colspan=\"3\"><div style=\"width: $per;\">$per</div></td>\n";
				print "</tr>\n";
			}
		}

		# ファイル名表示
		print "<tr>\n";
		print "<th id=\"FILE\">＼</th>\n";
		if ($dllog_flag) {
			print "<th>$title</th>\n";
			print "<th>Downloaded</th>\n";
		}
		else {
			print "<th colspan=\"2\">$title</th>\n";
		}
		print "<th>Count</th>\n";
		print "<th colspan=\"3\">Graph (Rate)</th>\n";
		print "</tr>\n";

		my($namecount, $adjust, $value);
		foreach (sort { $nameList{$b} <=> $nameList{$a} || $a cmp $b } keys %nameList) {
			my $number = sprintf("%03d", ++$namecount);
			if ($RowIndexFormat) {
				$adjust = ($nameList{$_} == $value) ? ++$adjust : 0;
				$number = sprintf("%03d", $namecount - $adjust);
				$value = $nameList{$_};
			}
			my $per = sprintf("%.1f%%", ($nameList{$_} / $TOTALLOGS) * 100);

			print "<tr>\n";
			print "<td>$number</td>\n";
			if ($dllog_flag && exists($lastdayList{$_})) {
				print "<td>$_</td>\n";
				print "<td>$lastdayList{$_}</td>\n";
				delete($lastdayList{$_});
			}
			else {
				print "<td colspan=\"2\">$_</td>\n";
			}
			print "<td class=\"r\">$nameList{$_}</td>\n";
			print "<td colspan=\"3\"><div style=\"width: $per;\">$per</div></td>\n";
			print "</tr>\n";
		}

		print "</table>\n";
		mainFooter(1);
	}
}

#======================================================
#	パーミッション変更
#======================================================
sub per_666 {
	my $file = shift;
	unless (!-e $file || -r $file && -w $file) {
		chmod(0666, $file) || system("chmod 0666 $file") && warn $?;
	}
}
sub per_600 {
	my $file = shift;
	my $per_mode = (stat($file))[2];
	$per_mode = sprintf("%o", $per_mode);
	$per_mode = substr($per_mode, 3, 6);

	if ($per_mode != 600) {
		chmod(0600, $file) || warn $!;
	}
}

#======================================================
#	上位バイト変換
#======================================================
sub higher_byte {
	my $byte = shift;

	return(($byte < 1024000) ? int($byte / 1024) . " KB" : sprintf("%.2f MB", $byte / (1024 * 1024)));
}

#======================================================
#	単位区切り
#======================================================
sub number_split {
	my $num = shift;
	1 while ($num =~ s/(.*\d)(\d{3})/$1,$2/);

	return $num;
}

#======================================================
#	差時間用の秒数変換
#======================================================
sub time_seconds {
	my $date = shift;
	my($year, $mon, $day) = split(/\//, $date);

	# 日時の正確な秒数を算出するのではないから最低限のみ
	$year -= 1970;
	$mon = int($mon);

	# 月は日数に換算する
	my $fullday = ("", 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365)[$mon];

	# 日付は1ヶ月を31日とする
	$day++ if ($mon =~ /^(?:[469]|11)$/);
	$day += ($year % 4 == 0) ? 2 : 3 if ($mon == 2);

	return((86400 * 365 * $year) + (86400 * $fullday) + (3600 * 24 * $day));
}

#======================================================
#	置き換え
#======================================================
sub str_escape {
	my $str = shift;
	$str =~ s/&/&amp;/g;
	$str =~ s/"/&quot;/g;
	$str =~ s/'/&#39;/g;
	$str =~ s/</&lt;/g;
	$str =~ s/>/&gt;/g;
	$str =~ s/,/%2c/g;
	$str =~ tr/\x0D\x0A//d;

	return $str;
}
sub str_cut {
	my $str = shift;
	$str =~ tr/-\.0-9A-Za-z_//cd;

	return $str;
}
sub url_encode {
	my $str = shift;
	$str =~ s/(\W)/"%" . unpack("H2", $1)/eg;

	return $str;
}

#======================================================
#	ログイン履歴
#======================================================
sub login_time {
	return unless ($LoginLogFile);

	my $login = shift;
	per_666($LoginLogFile);
	if ($login) {
		# 前回ログイン時間取得
		my $lastlogin = (stat($LoginLogFile))[9];

		open(OUT, "> $LoginLogFile") || warn $!;
		eval { flock(OUT, 2); };
		print OUT time . "\n$lastlogin";
		close(OUT);
	}
	else {
		open(IN, $LoginLogFile) || warn $!;
		eval { flock(IN, 1); };
		while (<IN>) {
			chomp;
			my($sec, $min, $hour, $mday, $mon, $year) = (localtime($_))[0..5];
			my $info = ($. == 1) ? "This" : "<br>Last";
			printf("$info Login Time: %04d/%02d/%02d %02d:%02d:%02d", $year + 1900, $mon + 1, $mday, $hour, $min, $sec);
		}
		close(IN);
	}
	per_600($LoginLogFile);
}

#======================================================
#	過去ログ送信
#======================================================
sub send_log {
	my $sendlog = shift;
	my $boundary = "----=_NextPart_" . times . time;

	open(MAIL, "| $SendmailPath -t") || warn $!;
	# メインヘッダ
	print MAIL "To: $AdminMailto\n";
	print MAIL "From: $AdminMailto\n";
	print MAIL "Subject: Past Download Log $sendlog\n";
	print MAIL "MIME-Version: 1.0\n";
	print MAIL "Content-Type: multipart/mixed; boundary=\"$boundary\"\n";
	print MAIL "\n";

	# 総ダウンロード数
	if ($TotalCountFile && -e $TotalCountFile) {
		# メッセージ用ヘッダ
		print MAIL "--$boundary\n";
		print MAIL "Content-Type: text/plain; charset=iso-2022-jp\n";
		print MAIL "Content-Transfer-Encoding: 7bit\n";
		print MAIL "\n";

		my(@date, %downloadList, $total, $count, $adjust, $value);
		per_666($TotalCountFile);
		open(IN, $TotalCountFile) || warn $!;
		eval { flock(IN, 1); };
		while (<IN>) {
			chomp;
			my($file, $dlcount, $firstdate, $lastdate) = split(/,/);

			push(@date, $firstdate, $lastdate);
			$downloadList{$file} = [$dlcount, "$firstdate - $lastdate"];
		}
		close(IN);
		per_600($TotalCountFile);

		foreach (sort { $downloadList{$b}->[0] <=> $downloadList{$a}->[0] } keys %downloadList) {
			$adjust = ($downloadList{$_}->[0] == $value) ? ++$adjust : 0;
			$total += $value = $downloadList{$_}->[0];
			my $rank = sprintf("%03d", ++$count - $adjust);

			print MAIL "$rank $_ $value $downloadList{$_}->[1]\n";
		}
		my $period = join(" - ", (sort @date)[0,-1]);

		print MAIL "\n--\n";
		print MAIL "$count Files $total Downloaded ($period)\n\n";
	}

	# 添付ファイル用ヘッダ
	print MAIL "--$boundary\n";
	print MAIL "Content-Type: application/octet-stream; name=\"$sendlog\"\n";
	print MAIL "Content-Transfer-Encoding: quoted-printable\n";
	print MAIL "Content-Disposition: attachment; filename=\"$sendlog\"\n";
	print MAIL "\n";

	# ファイル展開 (RFC 2045)
	open(IN, "$LogDir$sendlog") || warn $!;
	while (<IN>) {
		chomp;
		s/([^\x09\x20-\x3C\x3E-\x7E])/sprintf("=%02X", ord($1))/eg;
		s/([^\n]{70,72}[^=\n][0-9A-F]{0,2})/$1=\n/g;
		s/=\n$//;
		s/([\x09\x20])$/sprintf("=%02X", ord($1))/e;

		print MAIL "$_\n";
	}
	close(IN);
	print MAIL "\n";

	print MAIL "--$boundary--\n";
	close(MAIL);
}

#======================================================
#	エラーメッセージ
#======================================================
sub error {
	my($str, $code, $extra) = @_;

	# エラーログ記録
	if (($UnRecErrorCode) && $UnRecErrorCode =~ /^(?:[0-7]{1,8}|[0-6]\-[1-7])$/) {
		# 正規表現内のエラー番号は除外
		($code =~ /^[$UnRecErrorCode]$/) || logging($ErrLog, $str, "-", $extra);
	}
	else {
		logging($ErrLog, $str, "-", $extra);
	}

	mainHeader();
	mainHTML($str);
	print "</head>\n<body>\n";
	print "<dl>\n";
	print "<dt style=\"margin-bottom: 5px;\" class=\"red bo\">Download Error</dt>\n";
	unless ($code) {
		my $hostname = $ENV{'HTTP_HOST'} || $ENV{'SERVER_NAME'};

		print "<dd>参照元が不明なので参照元を送信できるようにしてから再度ダウンロードしてください。</dd>\n";
		print "<dd><em>Please send HTTP Referer, and try again.</em></dd>\n";
		print "<dt style=\"margin: 10px 0 3px 0;\">Norton Internet Security をご使用の場合</dt>\n";
		print "<dd>オプション → Web コンテンツ（拡張オプション → Web のタブ） → サイトを追加に <strong class=\"red\">$hostname</strong> を入力。</dd>\n";
		print "<dd>追加した <strong class=\"red\">$hostname</strong> を選択 → グローバル設定（プライバシー）のタブ";
		print " → 表\示したサイトについての情報（参照元）を許可にして OK をクリックしてください。</dd>\n";
		print "<dd style=\"margin-top: 10px;\">※バージョンによって項目の名称が異なります。</dd>\n";
		print "<dd>※この設定を行なうと $hostname が含まれるサイトに全て適用されます。</dd>\n";
	}
	elsif ($code == 1) {
		print "<dd>リクエストされたファイルは存在しません。</dd>\n";
		print "<dd><em>The requested file is not found.</em></dd>\n";
	}
	elsif ($code == 2) {
		print "<dd>ファイルの読み込みに失敗しました。しばらくしてから再度ダウンロードしてください。</dd>\n";
		print "<dd><em>It failed in opening this file. Please download it after a while.</em></dd>\n";
	}
	elsif ($code == 3) {
		print "<dd>不正なリクエストです。</dd>\n";
		print "<dd><em>It was wrong request.</em></dd>\n";
	}
	elsif ($code == 4) {
		print "<dd>ブラウザの設定でクッキーの受け入れを有効にしてください。</dd>\n";
		print "<dd><em>Please accept the HTTP Cookie.</em></dd>\n";
	}
	elsif ($code == 5) {
		print "<dd>ダウンロードの上限を超えましたので、24時間以上経過してからダウンロードしてください。</dd>\n";
		print "<dd><em>Please download again in 24 hours, because it is a limit of download.</em></dd>\n";
	}
	elsif ($code == 6) {
		(my $time = $extra) =~ tr/0-9//cd;
		print "<dd>$WaitTime 秒間の連続ダウンロード規制のため、あと $time 秒以上経過しないとダウンロードできません。</dd>\n";
		print "<dd><em>Consecutive download has been blocked for $WaitTime seconds.";
		print " Please download after it waits for $time seconds and over.</em></dd>\n";
	}
	else {
		print "<dd>許可しない参照元からのアクセスです。<!-- $SetReferer --></dd>\n";
		print "<dd><em>It is not access from accurate HTTP Referer.</em></dd>\n";
	}
	print "</dl>\n";
	mainFooter(3);
}
