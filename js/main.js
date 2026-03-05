//===============================================================
// メニュー制御用の関数とイベント設定（※バージョン2025-1）
//===============================================================
$(function(){
  //-------------------------------------------------
  // 変数の宣言
  //-------------------------------------------------
  const $menubar = $('#menubar');
  const $menubarHdr = $('#menubar_hdr');
  const breakPoint = 9999;	// ここがブレイクポイント指定箇所です

  // ▼ここを切り替えるだけで 2パターンを使い分け！
  //   false → “従来どおり”
  //   true  → “ハンバーガーが非表示の間は #menubar も非表示”
  const HIDE_MENUBAR_IF_HDR_HIDDEN = false;

  // タッチデバイスかどうかの判定
  const isTouchDevice = ('ontouchstart' in window) ||
                       (navigator.maxTouchPoints > 0) ||
                       (navigator.msMaxTouchPoints > 0);

  //-------------------------------------------------
  // debounce(処理の呼び出し頻度を抑制) 関数
  //-------------------------------------------------
  function debounce(fn, wait) {
    let timerId;
    return function(...args) {
      if (timerId) {
        clearTimeout(timerId);
      }
      timerId = setTimeout(() => {
        fn.apply(this, args);
      }, wait);
    };
  }

  //-------------------------------------------------
  // ドロップダウン用の初期化関数
  //-------------------------------------------------
  function initDropdown($menu, isTouch) {
    // ドロップダウンメニューが存在するliにクラス追加
    $menu.find('ul li').each(function() {
      if ($(this).find('ul').length) {
        $(this).addClass('ddmenu_parent');
        $(this).children('a').addClass('ddmenu');
      }
    });

    // ドロップダウン開閉のイベント設定
    if (isTouch) {
      // タッチデバイスの場合 → タップで開閉
      $menu.find('.ddmenu').on('click', function(e) {
        e.preventDefault();
        e.stopPropagation();
        const $dropdownMenu = $(this).siblings('ul');
        if ($dropdownMenu.is(':visible')) {
          $dropdownMenu.hide();
        } else {
          $menu.find('.ddmenu_parent ul').hide(); // 他を閉じる
          $dropdownMenu.show();
        }
      });
    } else {
      // PCの場合 → ホバーで開閉
      $menu.find('.ddmenu_parent').hover(
        function() {
          $(this).children('ul').show();
        },
        function() {
          $(this).children('ul').hide();
        }
      );
    }
  }

  //-------------------------------------------------
  // ハンバーガーメニューでの開閉制御関数
  //-------------------------------------------------
  function initHamburger($hamburger, $menu) {
    $hamburger.on('click', function() {
      $(this).toggleClass('ham');
      if ($(this).hasClass('ham')) {
        $menu.show();
        // ▼ ブレイクポイント未満でハンバーガーが開いたら body のスクロール禁止
        //    （メニューが画面いっぱいに fixed 表示されている時に背後をスクロールさせないため）
        if ($(window).width() < breakPoint) {
          $('body').addClass('noscroll');  // ★追加
        }
      } else {
        $menu.hide();
        // ▼ ハンバーガーを閉じたらスクロール禁止を解除
        if ($(window).width() < breakPoint) {
          $('body').removeClass('noscroll');  // ★追加
        }
      }
      // ドロップダウン部分も一旦閉じる
      $menu.find('.ddmenu_parent ul').hide();
    });
  }

  //-------------------------------------------------
  // レスポンシブ時の表示制御 (リサイズ時)
  //-------------------------------------------------
  const handleResize = debounce(function() {
    const windowWidth = $(window).width();

    // bodyクラスの制御 (small-screen / large-screen)
    if (windowWidth < breakPoint) {
      $('body').removeClass('large-screen').addClass('small-screen');
    } else {
      $('body').removeClass('small-screen').addClass('large-screen');
      // PC表示になったら、ハンバーガー解除 + メニューを開く
      $menubarHdr.removeClass('ham');
      $menubar.find('.ddmenu_parent ul').hide();

      // ▼ PC表示に切り替わったらスクロール禁止も解除しておく (保険的な意味合い)
      $('body').removeClass('noscroll'); // ★追加

      // ▼ #menubar を表示するか/しないかの切り替え
      if (HIDE_MENUBAR_IF_HDR_HIDDEN) {
        $menubarHdr.hide();
        $menubar.hide();
      } else {
        $menubarHdr.hide();
        $menubar.show();
      }
    }

    // スマホ(ブレイクポイント未満)のとき
    if (windowWidth < breakPoint) {
      $menubarHdr.show();
      if (!$menubarHdr.hasClass('ham')) {
        $menubar.hide();
        // ▼ ハンバーガーが閉じている状態ならスクロール禁止も解除
        $('body').removeClass('noscroll'); // ★追加
      }
    }
  }, 200);

  //-------------------------------------------------
  // 初期化
  //-------------------------------------------------
  // 1) ドロップダウン初期化 (#menubar)
  initDropdown($menubar, isTouchDevice);

  // 2) ハンバーガーメニュー初期化 (#menubar_hdr + #menubar)
  initHamburger($menubarHdr, $menubar);

  // 3) レスポンシブ表示の初期処理 & リサイズイベント
  handleResize();
  $(window).on('resize', handleResize);

  //-------------------------------------------------
  // アンカーリンク(#)のクリックイベント
  //-------------------------------------------------
  $menubar.find('a[href^="#"]').on('click', function() {
    // ドロップダウンメニューの親(a.ddmenu)のリンクはメニューを閉じない
    if ($(this).hasClass('ddmenu')) return;

    // スマホ表示＆ハンバーガーが開いている状態なら閉じる
    if ($menubarHdr.is(':visible') && $menubarHdr.hasClass('ham')) {
      $menubarHdr.removeClass('ham');
      $menubar.hide();
      $menubar.find('.ddmenu_parent ul').hide();
      // ハンバーガーが閉じたのでスクロール禁止を解除
      $('body').removeClass('noscroll'); // ★追加
    }
  });

  //-------------------------------------------------
  // 「header nav」など別メニューにドロップダウンだけ適用したい場合
  //-------------------------------------------------
  // 例：header nav へドロップダウンだけ適用（ハンバーガー連動なし）
  //initDropdown($('header nav'), isTouchDevice);
});


//===============================================================
// スムーススクロール（※バージョン2024-1）※通常タイプ
//===============================================================
$(function() {
    // ページ上部へ戻るボタンのセレクター
    var topButton = $('.pagetop');
    // ページトップボタン表示用のクラス名
    var scrollShow = 'pagetop-show';

    // スムーススクロールを実行する関数
    // targetにはスクロール先の要素のセレクターまたは'#'（ページトップ）を指定
    function smoothScroll(target) {
        // スクロール先の位置を計算（ページトップの場合は0、それ以外は要素の位置）
        var scrollTo = target === '#' ? 0 : $(target).offset().top;
        // アニメーションでスムーススクロールを実行
        $('html, body').animate({scrollTop: scrollTo}, 500);
    }

    // ページ内リンクとページトップへ戻るボタンにクリックイベントを設定
    $('a[href^="#"], .pagetop').click(function(e) {
        e.preventDefault(); // デフォルトのアンカー動作をキャンセル
        var id = $(this).attr('href') || '#'; // クリックされた要素のhref属性を取得、なければ'#'
        smoothScroll(id); // スムーススクロールを実行
    });

    // スクロールに応じてページトップボタンの表示/非表示を切り替え
    $(topButton).hide(); // 初期状態ではボタンを隠す
    $(window).scroll(function() {
        if($(this).scrollTop() >= 300) { // スクロール位置が300pxを超えたら
            $(topButton).fadeIn().addClass(scrollShow); // ボタンを表示
        } else {
            $(topButton).fadeOut().removeClass(scrollShow); // それ以外では非表示
        }
    });

    // ページロード時にURLのハッシュが存在する場合の処理
    if(window.location.hash) {
        // ページの最上部に即時スクロールする
        $('html, body').scrollTop(0);
        // 少し遅延させてからスムーススクロールを実行
        setTimeout(function() {
            smoothScroll(window.location.hash);
        }, 10);
    }
});


//===============================================================
// 画面の高さを取得
//===============================================================
function setDynamicHeight() {
  document.documentElement.style.setProperty('--vh', `${window.innerHeight}px`);
}

// 初回実行
setDynamicHeight();

// 画面リサイズ時にも更新
window.addEventListener('resize', setDynamicHeight);


//===============================================================
// スライドショー
//===============================================================
$(function() {
	var slides = $('#mainimg-parts .slide-parts');
	var slideCount = slides.length;
	var currentIndex = 0;

	slides.eq(currentIndex).css('opacity', 1).addClass('active');

	setInterval(function() {
		var nextIndex = (currentIndex + 1) % slideCount;
		slides.eq(currentIndex).css('opacity', 0).removeClass('active');
		slides.eq(nextIndex).css('opacity', 1).addClass('active');
		currentIndex = nextIndex;
	}, 5000); // 5秒ごとにスライドを切り替える
});

//===============================================================
// 汎用開閉処理
//===============================================================
$(function() {
	$('.openclose2-parts').next().hide();
	$('.openclose2-parts').click(function() {
		// クリックした要素に active クラスをトグルする
		$(this).toggleClass('active');
		$(this).next().slideToggle();
		// クリックされた要素以外の active クラスを除去し、その dd を閉じる
		$('.openclose2-parts').not(this).removeClass('active').next().slideUp();
	});
});

//===============================================================
// サムネイルの横スライドショー
//===============================================================
$(function() {
  var slideDuration = 1000; // アニメーション時間（ミリ秒）
  var autoSlideInterval = 3000; // 自動スライドの間隔（ミリ秒）

  var imagesPerView, slideBy;
  var slideInterval;
  var $slider = $('.slide-thumbnail2-parts');
  var $imgParts = $slider.find('.img-parts');
  var $divs = $imgParts.children('div').not('.clone');
  var totalImages = $divs.length;
  var isAnimating = false;
  var currentImageIndex = 0;

  function initSlider() {
      // スライドショーをリセット
      currentImageIndex = 0;

      // 既存のタイマーをクリア
      clearInterval($slider.data('interval'));

      // 既存のクローン要素とインジケータを削除
      $imgParts.find('.clone').remove();
      $slider.find('.slide-indicators-parts').empty();

      var windowWidth = $(window).width();

      if (windowWidth >= 801) {
          imagesPerView = 4;
          slideBy = 2;
      } else {
          imagesPerView = 2;
          slideBy = 1;
      }

      // 子要素をクローンして追加（無限ループのため）
      $divs.clone().addClass('clone').appendTo($imgParts);

      // インジケーターボタンを生成
      var $indicators = $slider.find('.slide-indicators-parts');
      var totalSlides = Math.ceil(totalImages / slideBy);
      for (var i = 0; i < totalSlides; i++) {
          $indicators.append('<span class="indicator" data-index="' + (i * slideBy) + '"></span>');
      }
      var $indicatorItems = $indicators.find('.indicator');

      // インジケーターボタンの状態を更新
      function updateIndicators() {
          var activeIndex = Math.floor(currentImageIndex / slideBy) % totalSlides;
          $indicatorItems.removeClass('active');
          $indicatorItems.eq(activeIndex).addClass('active');
      }

      // スライドを特定のインデックスに移動する関数
      function slideTo(index) {
          if (isAnimating) return;
          isAnimating = true;
          currentImageIndex = index;

          // アニメーションを設定
          $imgParts.css({
              'transition': 'transform ' + (slideDuration / 1000) + 's ease',
              'transform': 'translateX(' + (-currentImageIndex * (100 / imagesPerView)) + '%)'
          });

          updateIndicators();

          setTimeout(function() {
              // ループ処理
              if (currentImageIndex >= totalImages) {
                  // transitionを無効にして一瞬で戻す
                  $imgParts.css('transition', 'none');
                  $imgParts.css('transform', 'translateX(0)');
                  currentImageIndex = 0;
                  updateIndicators();

                  // 再描画を強制
                  $imgParts[0].offsetHeight;

                  // transitionを再設定
                  $imgParts.css('transition', 'transform ' + (slideDuration / 1000) + 's ease');
              }
              isAnimating = false;
          }, slideDuration);
      }

      // 初期位置にスライド
      $imgParts.css({
          'transition': 'none',
          'transform': 'translateX(0)'
      });
      updateIndicators();

      // スライドを自動的に進める
      function startAutoSlide() {
          slideInterval = setInterval(function() {
              slideTo(currentImageIndex + slideBy);
          }, autoSlideInterval);
          $slider.data('interval', slideInterval);
      }

      function stopAutoSlide() {
          clearInterval($slider.data('interval'));
      }

      startAutoSlide();

      // マウスオーバーでスライドを停止（モバイルデバイスでは無効）
      $slider.off('mouseenter mouseleave').on('mouseenter', function() {
          stopAutoSlide();
      }).on('mouseleave', function() {
          startAutoSlide();
      });

      // インジケーターボタンをクリックしたときの処理
      $indicatorItems.off('click').on('click', function() {
          var index = $(this).data('index');
          slideTo(index);
          // 自動再生を再開
          stopAutoSlide();
          startAutoSlide();
      });
  }

  // 初期化
  initSlider();

  // リサイズ時に再初期化（リセット）
  var resizeTimer;
  $(window).on('resize', function() {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(function() {
          initSlider();
      }, 250);
  });
});

//===============================================================
// ポップアップ
//===============================================================
$(function() {
	// セッション内でポップアップが既に表示されているかチェック
	if (!sessionStorage.getItem('popupShown')) {
		setTimeout(function(){
			if ($("#popup2-overlay-parts").length) {
				$("#popup2-overlay-parts").fadeIn(300);
			}
			$("#popup3-parts").fadeIn(300);
			sessionStorage.setItem('popupShown', 'true');
		}, 3000); // 3秒後にポップアップを表示
	}
	
	// 閉じるボタンのクリックイベント
	$(".close-btn-parts").click(function(){
		$("#popup3-parts").fadeOut(300);
		if ($("#popup2-overlay-parts").length) {
			$("#popup2-overlay-parts").fadeOut(300);
		}
	});
});

//===============================================================
// 詳細ページのサムネイル切り替え
//===============================================================
$(function() {
  // 初期表示: 各 .thumbnail-view に対して、直後の .thumbnail の最初の画像を表示
  $(".thumbnail-view-parts").each(function() {
      var firstThumbnailSrc = $(this).next(".thumbnail-parts").find("img:first").attr("src");
      var defaultImage = $("<img>").attr("src", firstThumbnailSrc);
      $(this).append(defaultImage);
  });

  // サムネイルがクリックされたときの動作
  $(".thumbnail-parts img").click(function() {
      var imgSrc = $(this).attr("src");
      var newImage = $("<img>").attr("src", imgSrc).hide();

      // このサムネイルの直前の .thumbnail-view 要素を取得
      var targetPhoto = $(this).parent(".thumbnail-parts").prev(".thumbnail-view-parts");

      targetPhoto.find("img").fadeOut(400, function() {
          targetPhoto.empty().append(newImage);
          newImage.fadeIn(400);
      });
  });
});
