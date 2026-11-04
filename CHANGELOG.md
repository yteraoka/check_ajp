# Changelog

## [v0.1.1](https://github.com/yteraoka/check_ajp/compare/v0.1.0...v0.1.1) - 2026-11-04

- Configure Renovate by @renovate[bot] in https://github.com/yteraoka/check_ajp/pull/1
- AJP 応答の解析でパケット長を検証する by @yteraoka in https://github.com/yteraoka/check_ajp/pull/13
- date ヘッダ名の誤字修正、go.mod 追加、-v 出力の無害化など by @yteraoka in https://github.com/yteraoka/check_ajp/pull/14
- User-Agent の既定値の条件が逆になっていたのを修正 by @yteraoka in https://github.com/yteraoka/check_ajp/pull/15
- PR 時に go test / format check / security check を実行する CI を追加 by @yteraoka in https://github.com/yteraoka/check_ajp/pull/16
- Update securego/gosec action to v2.30.0 by @renovate[bot] in https://github.com/yteraoka/check_ajp/pull/17
- req_attribute / ssl_key_size 属性を AJP13 の仕様どおりにエンコードする by @yteraoka in https://github.com/yteraoka/check_ajp/pull/18
- タイムアウト値の小数部が切り捨てられるのを修正 by @yteraoka in https://github.com/yteraoka/check_ajp/pull/19
- -k / -a の値の形式が不正なときに panic せず UNKNOWN で終了する by @yteraoka in https://github.com/yteraoka/check_ajp/pull/20
- 応答ボディをメモリに保持するサイズに上限を設ける by @yteraoka in https://github.com/yteraoka/check_ajp/pull/21
- 送信パケットのサイズを検証し、struc への依存をなくす by @yteraoka in https://github.com/yteraoka/check_ajp/pull/22
- IPv6 アドレスで接続先と remote_addr を正しく扱う by @yteraoka in https://github.com/yteraoka/check_ajp/pull/23
- secret をファイルまたは環境変数で渡せるようにする by @yteraoka in https://github.com/yteraoka/check_ajp/pull/24
- Release with tagpr by @yteraoka in https://github.com/yteraoka/check_ajp/pull/25
- Update Songmu/tagpr action to v1.22.0 by @renovate[bot] in https://github.com/yteraoka/check_ajp/pull/27

## [v0.1.0](https://github.com/yteraoka/check_ajp/commits/v0.1.0) - 2018-10-28
