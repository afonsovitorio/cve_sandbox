<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml"><head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<style type="text/css">
body {background-color: #fff; color: #222; font-family: sans-serif;}
pre {margin: 0; font-family: monospace;}
a:link {color: #009; text-decoration: none; background-color: #fff;}
a:hover {text-decoration: underline;}
table {border-collapse: collapse; border: 0; width: 934px; box-shadow: 1px 2px 3px #ccc;}
.center {text-align: center;}
.center table {margin: 1em auto; text-align: left;}
.center th {text-align: center !important;}
td, th {border: 1px solid #666; font-size: 75%; vertical-align: baseline; padding: 4px 5px;}
th {position: sticky; top: 0; background: inherit;}
h1 {font-size: 150%;}
h2 {font-size: 125%;}
.p {text-align: left;}
.e {background-color: #ccf; width: 300px; font-weight: bold;}
.h {background-color: #99c; font-weight: bold;}
.v {background-color: #ddd; max-width: 300px; overflow-x: auto; word-wrap: break-word;}
.v i {color: #999;}
img {float: right; border: 0;}
hr {width: 934px; background-color: #ccc; border: 0; height: 1px;}
</style>
<title>PHP 7.4.3-4ubuntu2.18 - phpinfo()</title><meta name="ROBOTS" content="NOINDEX,NOFOLLOW,NOARCHIVE"><style>@-webkit-keyframes swal2-show {
  0% {
    -webkit-transform: scale(0.7);
            transform: scale(0.7); }
  45% {
    -webkit-transform: scale(1.05);
            transform: scale(1.05); }
  80% {
    -webkit-transform: scale(0.95);
            transform: scale(0.95); }
  100% {
    -webkit-transform: scale(1);
            transform: scale(1); } }

@keyframes swal2-show {
  0% {
    -webkit-transform: scale(0.7);
            transform: scale(0.7); }
  45% {
    -webkit-transform: scale(1.05);
            transform: scale(1.05); }
  80% {
    -webkit-transform: scale(0.95);
            transform: scale(0.95); }
  100% {
    -webkit-transform: scale(1);
            transform: scale(1); } }

@-webkit-keyframes swal2-hide {
  0% {
    -webkit-transform: scale(1);
            transform: scale(1);
    opacity: 1; }
  100% {
    -webkit-transform: scale(0.5);
            transform: scale(0.5);
    opacity: 0; } }

@keyframes swal2-hide {
  0% {
    -webkit-transform: scale(1);
            transform: scale(1);
    opacity: 1; }
  100% {
    -webkit-transform: scale(0.5);
            transform: scale(0.5);
    opacity: 0; } }

@-webkit-keyframes swal2-animate-success-line-tip {
  0% {
    top: 1.1875em;
    left: .0625em;
    width: 0; }
  54% {
    top: 1.0625em;
    left: .125em;
    width: 0; }
  70% {
    top: 2.1875em;
    left: -.375em;
    width: 3.125em; }
  84% {
    top: 3em;
    left: 1.3125em;
    width: 1.0625em; }
  100% {
    top: 2.8125em;
    left: .875em;
    width: 1.5625em; } }

@keyframes swal2-animate-success-line-tip {
  0% {
    top: 1.1875em;
    left: .0625em;
    width: 0; }
  54% {
    top: 1.0625em;
    left: .125em;
    width: 0; }
  70% {
    top: 2.1875em;
    left: -.375em;
    width: 3.125em; }
  84% {
    top: 3em;
    left: 1.3125em;
    width: 1.0625em; }
  100% {
    top: 2.8125em;
    left: .875em;
    width: 1.5625em; } }

@-webkit-keyframes swal2-animate-success-line-long {
  0% {
    top: 3.375em;
    right: 2.875em;
    width: 0; }
  65% {
    top: 3.375em;
    right: 2.875em;
    width: 0; }
  84% {
    top: 2.1875em;
    right: 0;
    width: 3.4375em; }
  100% {
    top: 2.375em;
    right: .5em;
    width: 2.9375em; } }

@keyframes swal2-animate-success-line-long {
  0% {
    top: 3.375em;
    right: 2.875em;
    width: 0; }
  65% {
    top: 3.375em;
    right: 2.875em;
    width: 0; }
  84% {
    top: 2.1875em;
    right: 0;
    width: 3.4375em; }
  100% {
    top: 2.375em;
    right: .5em;
    width: 2.9375em; } }

@-webkit-keyframes swal2-rotate-success-circular-line {
  0% {
    -webkit-transform: rotate(-45deg);
            transform: rotate(-45deg); }
  5% {
    -webkit-transform: rotate(-45deg);
            transform: rotate(-45deg); }
  12% {
    -webkit-transform: rotate(-405deg);
            transform: rotate(-405deg); }
  100% {
    -webkit-transform: rotate(-405deg);
            transform: rotate(-405deg); } }

@keyframes swal2-rotate-success-circular-line {
  0% {
    -webkit-transform: rotate(-45deg);
            transform: rotate(-45deg); }
  5% {
    -webkit-transform: rotate(-45deg);
            transform: rotate(-45deg); }
  12% {
    -webkit-transform: rotate(-405deg);
            transform: rotate(-405deg); }
  100% {
    -webkit-transform: rotate(-405deg);
            transform: rotate(-405deg); } }

@-webkit-keyframes swal2-animate-error-x-mark {
  0% {
    margin-top: 1.625em;
    -webkit-transform: scale(0.4);
            transform: scale(0.4);
    opacity: 0; }
  50% {
    margin-top: 1.625em;
    -webkit-transform: scale(0.4);
            transform: scale(0.4);
    opacity: 0; }
  80% {
    margin-top: -.375em;
    -webkit-transform: scale(1.15);
            transform: scale(1.15); }
  100% {
    margin-top: 0;
    -webkit-transform: scale(1);
            transform: scale(1);
    opacity: 1; } }

@keyframes swal2-animate-error-x-mark {
  0% {
    margin-top: 1.625em;
    -webkit-transform: scale(0.4);
            transform: scale(0.4);
    opacity: 0; }
  50% {
    margin-top: 1.625em;
    -webkit-transform: scale(0.4);
            transform: scale(0.4);
    opacity: 0; }
  80% {
    margin-top: -.375em;
    -webkit-transform: scale(1.15);
            transform: scale(1.15); }
  100% {
    margin-top: 0;
    -webkit-transform: scale(1);
            transform: scale(1);
    opacity: 1; } }

@-webkit-keyframes swal2-animate-error-icon {
  0% {
    -webkit-transform: rotateX(100deg);
            transform: rotateX(100deg);
    opacity: 0; }
  100% {
    -webkit-transform: rotateX(0deg);
            transform: rotateX(0deg);
    opacity: 1; } }

@keyframes swal2-animate-error-icon {
  0% {
    -webkit-transform: rotateX(100deg);
            transform: rotateX(100deg);
    opacity: 0; }
  100% {
    -webkit-transform: rotateX(0deg);
            transform: rotateX(0deg);
    opacity: 1; } }

body.swal2-toast-shown.swal2-has-input > .swal2-container > .swal2-toast {
  flex-direction: column;
  align-items: stretch; }
  body.swal2-toast-shown.swal2-has-input > .swal2-container > .swal2-toast .swal2-actions {
    flex: 1;
    align-self: stretch;
    justify-content: flex-end;
    height: 2.2em; }
  body.swal2-toast-shown.swal2-has-input > .swal2-container > .swal2-toast .swal2-loading {
    justify-content: center; }
  body.swal2-toast-shown.swal2-has-input > .swal2-container > .swal2-toast .swal2-input {
    height: 2em;
    margin: .3125em auto;
    font-size: 1em; }
  body.swal2-toast-shown.swal2-has-input > .swal2-container > .swal2-toast .swal2-validationerror {
    font-size: 1em; }

body.swal2-toast-shown > .swal2-container {
  position: fixed;
  background-color: transparent; }
  body.swal2-toast-shown > .swal2-container.swal2-shown {
    background-color: transparent; }
  body.swal2-toast-shown > .swal2-container.swal2-top {
    top: 0;
    right: auto;
    bottom: auto;
    left: 50%;
    -webkit-transform: translateX(-50%);
            transform: translateX(-50%); }
  body.swal2-toast-shown > .swal2-container.swal2-top-end, body.swal2-toast-shown > .swal2-container.swal2-top-right {
    top: 0;
    right: 0;
    bottom: auto;
    left: auto; }
  body.swal2-toast-shown > .swal2-container.swal2-top-start, body.swal2-toast-shown > .swal2-container.swal2-top-left {
    top: 0;
    right: auto;
    bottom: auto;
    left: 0; }
  body.swal2-toast-shown > .swal2-container.swal2-center-start, body.swal2-toast-shown > .swal2-container.swal2-center-left {
    top: 50%;
    right: auto;
    bottom: auto;
    left: 0;
    -webkit-transform: translateY(-50%);
            transform: translateY(-50%); }
  body.swal2-toast-shown > .swal2-container.swal2-center {
    top: 50%;
    right: auto;
    bottom: auto;
    left: 50%;
    -webkit-transform: translate(-50%, -50%);
            transform: translate(-50%, -50%); }
  body.swal2-toast-shown > .swal2-container.swal2-center-end, body.swal2-toast-shown > .swal2-container.swal2-center-right {
    top: 50%;
    right: 0;
    bottom: auto;
    left: auto;
    -webkit-transform: translateY(-50%);
            transform: translateY(-50%); }
  body.swal2-toast-shown > .swal2-container.swal2-bottom-start, body.swal2-toast-shown > .swal2-container.swal2-bottom-left {
    top: auto;
    right: auto;
    bottom: 0;
    left: 0; }
  body.swal2-toast-shown > .swal2-container.swal2-bottom {
    top: auto;
    right: auto;
    bottom: 0;
    left: 50%;
    -webkit-transform: translateX(-50%);
            transform: translateX(-50%); }
  body.swal2-toast-shown > .swal2-container.swal2-bottom-end, body.swal2-toast-shown > .swal2-container.swal2-bottom-right {
    top: auto;
    right: 0;
    bottom: 0;
    left: auto; }

.swal2-popup.swal2-toast {
  flex-direction: row;
  align-items: center;
  width: auto;
  padding: 0.625em;
  box-shadow: 0 0 0.625em #d9d9d9;
  overflow-y: hidden; }
  .swal2-popup.swal2-toast .swal2-header {
    flex-direction: row; }
  .swal2-popup.swal2-toast .swal2-title {
    justify-content: flex-start;
    margin: 0 .6em;
    font-size: 1em; }
  .swal2-popup.swal2-toast .swal2-close {
    position: initial; }
  .swal2-popup.swal2-toast .swal2-content {
    justify-content: flex-start;
    font-size: 1em; }
  .swal2-popup.swal2-toast .swal2-icon {
    width: 2em;
    min-width: 2em;
    height: 2em;
    margin: 0; }
    .swal2-popup.swal2-toast .swal2-icon-text {
      font-size: 2em;
      font-weight: bold;
      line-height: 1em; }
    .swal2-popup.swal2-toast .swal2-icon.swal2-success .swal2-success-ring {
      width: 2em;
      height: 2em; }
    .swal2-popup.swal2-toast .swal2-icon.swal2-error [class^='swal2-x-mark-line'] {
      top: .875em;
      width: 1.375em; }
      .swal2-popup.swal2-toast .swal2-icon.swal2-error [class^='swal2-x-mark-line'][class$='left'] {
        left: .3125em; }
      .swal2-popup.swal2-toast .swal2-icon.swal2-error [class^='swal2-x-mark-line'][class$='right'] {
        right: .3125em; }
  .swal2-popup.swal2-toast .swal2-actions {
    height: auto;
    margin: 0 .3125em; }
  .swal2-popup.swal2-toast .swal2-styled {
    margin: 0 .3125em;
    padding: .3125em .625em;
    font-size: 1em; }
    .swal2-popup.swal2-toast .swal2-styled:focus {
      box-shadow: 0 0 0 0.0625em #fff, 0 0 0 0.125em rgba(50, 100, 150, 0.4); }
  .swal2-popup.swal2-toast .swal2-success {
    border-color: #a5dc86; }
    .swal2-popup.swal2-toast .swal2-success [class^='swal2-success-circular-line'] {
      position: absolute;
      width: 2em;
      height: 2.8125em;
      -webkit-transform: rotate(45deg);
              transform: rotate(45deg);
      border-radius: 50%; }
      .swal2-popup.swal2-toast .swal2-success [class^='swal2-success-circular-line'][class$='left'] {
        top: -.25em;
        left: -.9375em;
        -webkit-transform: rotate(-45deg);
                transform: rotate(-45deg);
        -webkit-transform-origin: 2em 2em;
                transform-origin: 2em 2em;
        border-radius: 4em 0 0 4em; }
      .swal2-popup.swal2-toast .swal2-success [class^='swal2-success-circular-line'][class$='right'] {
        top: -.25em;
        left: .9375em;
        -webkit-transform-origin: 0 2em;
                transform-origin: 0 2em;
        border-radius: 0 4em 4em 0; }
    .swal2-popup.swal2-toast .swal2-success .swal2-success-ring {
      width: 2em;
      height: 2em; }
    .swal2-popup.swal2-toast .swal2-success .swal2-success-fix {
      top: 0;
      left: .4375em;
      width: .4375em;
      height: 2.6875em; }
    .swal2-popup.swal2-toast .swal2-success [class^='swal2-success-line'] {
      height: .3125em; }
      .swal2-popup.swal2-toast .swal2-success [class^='swal2-success-line'][class$='tip'] {
        top: 1.125em;
        left: .1875em;
        width: .75em; }
      .swal2-popup.swal2-toast .swal2-success [class^='swal2-success-line'][class$='long'] {
        top: .9375em;
        right: .1875em;
        width: 1.375em; }
  .swal2-popup.swal2-toast.swal2-show {
    -webkit-animation: showSweetToast .5s;
            animation: showSweetToast .5s; }
  .swal2-popup.swal2-toast.swal2-hide {
    -webkit-animation: hideSweetToast .2s forwards;
            animation: hideSweetToast .2s forwards; }
  .swal2-popup.swal2-toast .swal2-animate-success-icon .swal2-success-line-tip {
    -webkit-animation: animate-toast-success-tip .75s;
            animation: animate-toast-success-tip .75s; }
  .swal2-popup.swal2-toast .swal2-animate-success-icon .swal2-success-line-long {
    -webkit-animation: animate-toast-success-long .75s;
            animation: animate-toast-success-long .75s; }

@-webkit-keyframes showSweetToast {
  0% {
    -webkit-transform: translateY(-0.625em) rotateZ(2deg);
            transform: translateY(-0.625em) rotateZ(2deg);
    opacity: 0; }
  33% {
    -webkit-transform: translateY(0) rotateZ(-2deg);
            transform: translateY(0) rotateZ(-2deg);
    opacity: .5; }
  66% {
    -webkit-transform: translateY(0.3125em) rotateZ(2deg);
            transform: translateY(0.3125em) rotateZ(2deg);
    opacity: .7; }
  100% {
    -webkit-transform: translateY(0) rotateZ(0);
            transform: translateY(0) rotateZ(0);
    opacity: 1; } }

@keyframes showSweetToast {
  0% {
    -webkit-transform: translateY(-0.625em) rotateZ(2deg);
            transform: translateY(-0.625em) rotateZ(2deg);
    opacity: 0; }
  33% {
    -webkit-transform: translateY(0) rotateZ(-2deg);
            transform: translateY(0) rotateZ(-2deg);
    opacity: .5; }
  66% {
    -webkit-transform: translateY(0.3125em) rotateZ(2deg);
            transform: translateY(0.3125em) rotateZ(2deg);
    opacity: .7; }
  100% {
    -webkit-transform: translateY(0) rotateZ(0);
            transform: translateY(0) rotateZ(0);
    opacity: 1; } }

@-webkit-keyframes hideSweetToast {
  0% {
    opacity: 1; }
  33% {
    opacity: .5; }
  100% {
    -webkit-transform: rotateZ(1deg);
            transform: rotateZ(1deg);
    opacity: 0; } }

@keyframes hideSweetToast {
  0% {
    opacity: 1; }
  33% {
    opacity: .5; }
  100% {
    -webkit-transform: rotateZ(1deg);
            transform: rotateZ(1deg);
    opacity: 0; } }

@-webkit-keyframes animate-toast-success-tip {
  0% {
    top: .5625em;
    left: .0625em;
    width: 0; }
  54% {
    top: .125em;
    left: .125em;
    width: 0; }
  70% {
    top: .625em;
    left: -.25em;
    width: 1.625em; }
  84% {
    top: 1.0625em;
    left: .75em;
    width: .5em; }
  100% {
    top: 1.125em;
    left: .1875em;
    width: .75em; } }

@keyframes animate-toast-success-tip {
  0% {
    top: .5625em;
    left: .0625em;
    width: 0; }
  54% {
    top: .125em;
    left: .125em;
    width: 0; }
  70% {
    top: .625em;
    left: -.25em;
    width: 1.625em; }
  84% {
    top: 1.0625em;
    left: .75em;
    width: .5em; }
  100% {
    top: 1.125em;
    left: .1875em;
    width: .75em; } }

@-webkit-keyframes animate-toast-success-long {
  0% {
    top: 1.625em;
    right: 1.375em;
    width: 0; }
  65% {
    top: 1.25em;
    right: .9375em;
    width: 0; }
  84% {
    top: .9375em;
    right: 0;
    width: 1.125em; }
  100% {
    top: .9375em;
    right: .1875em;
    width: 1.375em; } }

@keyframes animate-toast-success-long {
  0% {
    top: 1.625em;
    right: 1.375em;
    width: 0; }
  65% {
    top: 1.25em;
    right: .9375em;
    width: 0; }
  84% {
    top: .9375em;
    right: 0;
    width: 1.125em; }
  100% {
    top: .9375em;
    right: .1875em;
    width: 1.375em; } }

html.swal2-shown:not(.swal2-no-backdrop):not(.swal2-toast-shown),
body.swal2-shown:not(.swal2-no-backdrop):not(.swal2-toast-shown) {
  height: auto;
  overflow-y: hidden; }

body.swal2-no-backdrop .swal2-shown {
  top: auto;
  right: auto;
  bottom: auto;
  left: auto;
  background-color: transparent; }
  body.swal2-no-backdrop .swal2-shown > .swal2-modal {
    box-shadow: 0 0 10px rgba(0, 0, 0, 0.4); }
  body.swal2-no-backdrop .swal2-shown.swal2-top {
    top: 0;
    left: 50%;
    -webkit-transform: translateX(-50%);
            transform: translateX(-50%); }
  body.swal2-no-backdrop .swal2-shown.swal2-top-start, body.swal2-no-backdrop .swal2-shown.swal2-top-left {
    top: 0;
    left: 0; }
  body.swal2-no-backdrop .swal2-shown.swal2-top-end, body.swal2-no-backdrop .swal2-shown.swal2-top-right {
    top: 0;
    right: 0; }
  body.swal2-no-backdrop .swal2-shown.swal2-center {
    top: 50%;
    left: 50%;
    -webkit-transform: translate(-50%, -50%);
            transform: translate(-50%, -50%); }
  body.swal2-no-backdrop .swal2-shown.swal2-center-start, body.swal2-no-backdrop .swal2-shown.swal2-center-left {
    top: 50%;
    left: 0;
    -webkit-transform: translateY(-50%);
            transform: translateY(-50%); }
  body.swal2-no-backdrop .swal2-shown.swal2-center-end, body.swal2-no-backdrop .swal2-shown.swal2-center-right {
    top: 50%;
    right: 0;
    -webkit-transform: translateY(-50%);
            transform: translateY(-50%); }
  body.swal2-no-backdrop .swal2-shown.swal2-bottom {
    bottom: 0;
    left: 50%;
    -webkit-transform: translateX(-50%);
            transform: translateX(-50%); }
  body.swal2-no-backdrop .swal2-shown.swal2-bottom-start, body.swal2-no-backdrop .swal2-shown.swal2-bottom-left {
    bottom: 0;
    left: 0; }
  body.swal2-no-backdrop .swal2-shown.swal2-bottom-end, body.swal2-no-backdrop .swal2-shown.swal2-bottom-right {
    right: 0;
    bottom: 0; }

.swal2-container {
  display: flex;
  position: fixed;
  top: 0;
  right: 0;
  bottom: 0;
  left: 0;
  flex-direction: row;
  align-items: center;
  justify-content: center;
  padding: 10px;
  background-color: transparent;
  z-index: 1060;
  overflow-x: hidden;
  -webkit-overflow-scrolling: touch; }
  .swal2-container.swal2-top {
    align-items: flex-start; }
  .swal2-container.swal2-top-start, .swal2-container.swal2-top-left {
    align-items: flex-start;
    justify-content: flex-start; }
  .swal2-container.swal2-top-end, .swal2-container.swal2-top-right {
    align-items: flex-start;
    justify-content: flex-end; }
  .swal2-container.swal2-center {
    align-items: center; }
  .swal2-container.swal2-center-start, .swal2-container.swal2-center-left {
    align-items: center;
    justify-content: flex-start; }
  .swal2-container.swal2-center-end, .swal2-container.swal2-center-right {
    align-items: center;
    justify-content: flex-end; }
  .swal2-container.swal2-bottom {
    align-items: flex-end; }
  .swal2-container.swal2-bottom-start, .swal2-container.swal2-bottom-left {
    align-items: flex-end;
    justify-content: flex-start; }
  .swal2-container.swal2-bottom-end, .swal2-container.swal2-bottom-right {
    align-items: flex-end;
    justify-content: flex-end; }
  .swal2-container.swal2-grow-fullscreen > .swal2-modal {
    display: flex !important;
    flex: 1;
    align-self: stretch;
    justify-content: center; }
  .swal2-container.swal2-grow-row > .swal2-modal {
    display: flex !important;
    flex: 1;
    align-content: center;
    justify-content: center; }
  .swal2-container.swal2-grow-column {
    flex: 1;
    flex-direction: column; }
    .swal2-container.swal2-grow-column.swal2-top, .swal2-container.swal2-grow-column.swal2-center, .swal2-container.swal2-grow-column.swal2-bottom {
      align-items: center; }
    .swal2-container.swal2-grow-column.swal2-top-start, .swal2-container.swal2-grow-column.swal2-center-start, .swal2-container.swal2-grow-column.swal2-bottom-start, .swal2-container.swal2-grow-column.swal2-top-left, .swal2-container.swal2-grow-column.swal2-center-left, .swal2-container.swal2-grow-column.swal2-bottom-left {
      align-items: flex-start; }
    .swal2-container.swal2-grow-column.swal2-top-end, .swal2-container.swal2-grow-column.swal2-center-end, .swal2-container.swal2-grow-column.swal2-bottom-end, .swal2-container.swal2-grow-column.swal2-top-right, .swal2-container.swal2-grow-column.swal2-center-right, .swal2-container.swal2-grow-column.swal2-bottom-right {
      align-items: flex-end; }
    .swal2-container.swal2-grow-column > .swal2-modal {
      display: flex !important;
      flex: 1;
      align-content: center;
      justify-content: center; }
  .swal2-container:not(.swal2-top):not(.swal2-top-start):not(.swal2-top-end):not(.swal2-top-left):not(.swal2-top-right):not(.swal2-center-start):not(.swal2-center-end):not(.swal2-center-left):not(.swal2-center-right):not(.swal2-bottom):not(.swal2-bottom-start):not(.swal2-bottom-end):not(.swal2-bottom-left):not(.swal2-bottom-right) > .swal2-modal {
    margin: auto; }
  @media all and (-ms-high-contrast: none), (-ms-high-contrast: active) {
    .swal2-container .swal2-modal {
      margin: 0 !important; } }
  .swal2-container.swal2-fade {
    transition: background-color .1s; }
  .swal2-container.swal2-shown {
    background-color: rgba(0, 0, 0, 0.4); }

.swal2-popup {
  display: none;
  position: relative;
  flex-direction: column;
  justify-content: center;
  width: 32em;
  max-width: 100%;
  padding: 1.25em;
  border-radius: 0.3125em;
  background: #fff;
  font-family: inherit;
  font-size: 1rem;
  box-sizing: border-box; }
  .swal2-popup:focus {
    outline: none; }
  .swal2-popup.swal2-loading {
    overflow-y: hidden; }
  .swal2-popup .swal2-header {
    display: flex;
    flex-direction: column;
    align-items: center; }
  .swal2-popup .swal2-title {
    display: block;
    position: relative;
    max-width: 100%;
    margin: 0 0 0.4em;
    padding: 0;
    color: #595959;
    font-size: 1.875em;
    font-weight: 600;
    text-align: center;
    text-transform: none;
    word-wrap: break-word; }
  .swal2-popup .swal2-actions {
    align-items: center;
    justify-content: center;
    margin: 1.25em auto 0; }
    .swal2-popup .swal2-actions:not(.swal2-loading) .swal2-styled[disabled] {
      opacity: .4; }
    .swal2-popup .swal2-actions:not(.swal2-loading) .swal2-styled:hover {
      background-image: linear-gradient(rgba(0, 0, 0, 0.1), rgba(0, 0, 0, 0.1)); }
    .swal2-popup .swal2-actions:not(.swal2-loading) .swal2-styled:active {
      background-image: linear-gradient(rgba(0, 0, 0, 0.2), rgba(0, 0, 0, 0.2)); }
    .swal2-popup .swal2-actions.swal2-loading .swal2-styled.swal2-confirm {
      width: 2.5em;
      height: 2.5em;
      margin: .46875em;
      padding: 0;
      border: .25em solid transparent;
      border-radius: 100%;
      border-color: transparent;
      background-color: transparent !important;
      color: transparent;
      cursor: default;
      box-sizing: border-box;
      -webkit-animation: swal2-rotate-loading 1.5s linear 0s infinite normal;
              animation: swal2-rotate-loading 1.5s linear 0s infinite normal;
      -webkit-user-select: none;
         -moz-user-select: none;
          -ms-user-select: none;
              user-select: none; }
    .swal2-popup .swal2-actions.swal2-loading .swal2-styled.swal2-cancel {
      margin-right: 30px;
      margin-left: 30px; }
    .swal2-popup .swal2-actions.swal2-loading :not(.swal2-styled).swal2-confirm::after {
      display: inline-block;
      width: 15px;
      height: 15px;
      margin-left: 5px;
      border: 3px solid #999999;
      border-radius: 50%;
      border-right-color: transparent;
      box-shadow: 1px 1px 1px #fff;
      content: '';
      -webkit-animation: swal2-rotate-loading 1.5s linear 0s infinite normal;
              animation: swal2-rotate-loading 1.5s linear 0s infinite normal; }
  .swal2-popup .swal2-styled {
    margin: 0 .3125em;
    padding: .625em 2em;
    font-weight: 500;
    box-shadow: none; }
    .swal2-popup .swal2-styled:not([disabled]) {
      cursor: pointer; }
    .swal2-popup .swal2-styled.swal2-confirm {
      border: 0;
      border-radius: 0.25em;
      background: initial;
      background-color: #3085d6;
      color: #fff;
      font-size: 1.0625em; }
    .swal2-popup .swal2-styled.swal2-cancel {
      border: 0;
      border-radius: 0.25em;
      background: initial;
      background-color: #aaa;
      color: #fff;
      font-size: 1.0625em; }
    .swal2-popup .swal2-styled:focus {
      outline: none;
      box-shadow: 0 0 0 2px #fff, 0 0 0 4px rgba(50, 100, 150, 0.4); }
    .swal2-popup .swal2-styled::-moz-focus-inner {
      border: 0; }
  .swal2-popup .swal2-footer {
    justify-content: center;
    margin: 1.25em 0 0;
    padding-top: 1em;
    border-top: 1px solid #eee;
    color: #545454;
    font-size: 1em; }
  .swal2-popup .swal2-image {
    max-width: 100%;
    margin: 1.25em auto; }
  .swal2-popup .swal2-close {
    position: absolute;
    top: 0;
    right: 0;
    justify-content: center;
    width: 1.2em;
    min-width: 1.2em;
    height: 1.2em;
    margin: 0;
    padding: 0;
    transition: color 0.1s ease-out;
    border: none;
    border-radius: 0;
    background: transparent;
    color: #cccccc;
    font-family: serif;
    font-size: calc(2.5em - 0.25em);
    line-height: 1.2em;
    cursor: pointer; }
    .swal2-popup .swal2-close:hover {
      -webkit-transform: none;
              transform: none;
      color: #f27474; }
  .swal2-popup > .swal2-input,
  .swal2-popup > .swal2-file,
  .swal2-popup > .swal2-textarea,
  .swal2-popup > .swal2-select,
  .swal2-popup > .swal2-radio,
  .swal2-popup > .swal2-checkbox {
    display: none; }
  .swal2-popup .swal2-content {
    justify-content: center;
    margin: 0;
    padding: 0;
    color: #545454;
    font-size: 1.125em;
    font-weight: 300;
    line-height: normal;
    word-wrap: break-word; }
  .swal2-popup #swal2-content {
    text-align: center; }
  .swal2-popup .swal2-input,
  .swal2-popup .swal2-file,
  .swal2-popup .swal2-textarea,
  .swal2-popup .swal2-select,
  .swal2-popup .swal2-radio,
  .swal2-popup .swal2-checkbox {
    margin: 1em auto; }
  .swal2-popup .swal2-input,
  .swal2-popup .swal2-file,
  .swal2-popup .swal2-textarea {
    width: 100%;
    transition: border-color .3s, box-shadow .3s;
    border: 1px solid #d9d9d9;
    border-radius: 0.1875em;
    font-size: 1.125em;
    box-shadow: inset 0 1px 1px rgba(0, 0, 0, 0.06);
    box-sizing: border-box; }
    .swal2-popup .swal2-input.swal2-inputerror,
    .swal2-popup .swal2-file.swal2-inputerror,
    .swal2-popup .swal2-textarea.swal2-inputerror {
      border-color: #f27474 !important;
      box-shadow: 0 0 2px #f27474 !important; }
    .swal2-popup .swal2-input:focus,
    .swal2-popup .swal2-file:focus,
    .swal2-popup .swal2-textarea:focus {
      border: 1px solid #b4dbed;
      outline: none;
      box-shadow: 0 0 3px #c4e6f5; }
    .swal2-popup .swal2-input::-webkit-input-placeholder,
    .swal2-popup .swal2-file::-webkit-input-placeholder,
    .swal2-popup .swal2-textarea::-webkit-input-placeholder {
      color: #cccccc; }
    .swal2-popup .swal2-input:-ms-input-placeholder,
    .swal2-popup .swal2-file:-ms-input-placeholder,
    .swal2-popup .swal2-textarea:-ms-input-placeholder {
      color: #cccccc; }
    .swal2-popup .swal2-input::-ms-input-placeholder,
    .swal2-popup .swal2-file::-ms-input-placeholder,
    .swal2-popup .swal2-textarea::-ms-input-placeholder {
      color: #cccccc; }
    .swal2-popup .swal2-input::placeholder,
    .swal2-popup .swal2-file::placeholder,
    .swal2-popup .swal2-textarea::placeholder {
      color: #cccccc; }
  .swal2-popup .swal2-range input {
    width: 80%; }
  .swal2-popup .swal2-range output {
    width: 20%;
    font-weight: 600;
    text-align: center; }
  .swal2-popup .swal2-range input,
  .swal2-popup .swal2-range output {
    height: 2.625em;
    margin: 1em auto;
    padding: 0;
    font-size: 1.125em;
    line-height: 2.625em; }
  .swal2-popup .swal2-input {
    height: 2.625em;
    padding: 0.75em; }
    .swal2-popup .swal2-input[type='number'] {
      max-width: 10em; }
  .swal2-popup .swal2-file {
    font-size: 1.125em; }
  .swal2-popup .swal2-textarea {
    height: 6.75em;
    padding: 0.75em; }
  .swal2-popup .swal2-select {
    min-width: 50%;
    max-width: 100%;
    padding: .375em .625em;
    color: #545454;
    font-size: 1.125em; }
  .swal2-popup .swal2-radio,
  .swal2-popup .swal2-checkbox {
    align-items: center;
    justify-content: center; }
    .swal2-popup .swal2-radio label,
    .swal2-popup .swal2-checkbox label {
      margin: 0 .6em;
      font-size: 1.125em; }
    .swal2-popup .swal2-radio input,
    .swal2-popup .swal2-checkbox input {
      margin: 0 .4em; }
  .swal2-popup .swal2-validationerror {
    display: none;
    align-items: center;
    justify-content: center;
    padding: 0.625em;
    background: #f0f0f0;
    color: #666666;
    font-size: 1em;
    font-weight: 300;
    overflow: hidden; }
    .swal2-popup .swal2-validationerror::before {
      display: inline-block;
      width: 1.5em;
      height: 1.5em;
      margin: 0 .625em;
      border-radius: 50%;
      background-color: #f27474;
      color: #fff;
      font-weight: 600;
      line-height: 1.5em;
      text-align: center;
      content: '!';
      zoom: normal; }

@supports (-ms-accelerator: true) {
  .swal2-range input {
    width: 100% !important; }
  .swal2-range output {
    display: none; } }

@media all and (-ms-high-contrast: none), (-ms-high-contrast: active) {
  .swal2-range input {
    width: 100% !important; }
  .swal2-range output {
    display: none; } }

.swal2-icon {
  position: relative;
  justify-content: center;
  width: 5em;
  height: 5em;
  margin: 1.25em auto 1.875em;
  border: .25em solid transparent;
  border-radius: 50%;
  line-height: 5em;
  cursor: default;
  box-sizing: content-box;
  -webkit-user-select: none;
     -moz-user-select: none;
      -ms-user-select: none;
          user-select: none;
  zoom: normal; }
  .swal2-icon-text {
    font-size: 3.75em; }
  .swal2-icon.swal2-error {
    border-color: #f27474; }
    .swal2-icon.swal2-error .swal2-x-mark {
      position: relative;
      flex-grow: 1; }
    .swal2-icon.swal2-error [class^='swal2-x-mark-line'] {
      display: block;
      position: absolute;
      top: 2.3125em;
      width: 2.9375em;
      height: .3125em;
      border-radius: .125em;
      background-color: #f27474; }
      .swal2-icon.swal2-error [class^='swal2-x-mark-line'][class$='left'] {
        left: 1.0625em;
        -webkit-transform: rotate(45deg);
                transform: rotate(45deg); }
      .swal2-icon.swal2-error [class^='swal2-x-mark-line'][class$='right'] {
        right: 1em;
        -webkit-transform: rotate(-45deg);
                transform: rotate(-45deg); }
  .swal2-icon.swal2-warning {
    border-color: #facea8;
    color: #f8bb86; }
  .swal2-icon.swal2-info {
    border-color: #9de0f6;
    color: #3fc3ee; }
  .swal2-icon.swal2-question {
    border-color: #c9dae1;
    color: #87adbd; }
  .swal2-icon.swal2-success {
    border-color: #a5dc86; }
    .swal2-icon.swal2-success [class^='swal2-success-circular-line'] {
      position: absolute;
      width: 3.75em;
      height: 7.5em;
      -webkit-transform: rotate(45deg);
              transform: rotate(45deg);
      border-radius: 50%; }
      .swal2-icon.swal2-success [class^='swal2-success-circular-line'][class$='left'] {
        top: -.4375em;
        left: -2.0635em;
        -webkit-transform: rotate(-45deg);
                transform: rotate(-45deg);
        -webkit-transform-origin: 3.75em 3.75em;
                transform-origin: 3.75em 3.75em;
        border-radius: 7.5em 0 0 7.5em; }
      .swal2-icon.swal2-success [class^='swal2-success-circular-line'][class$='right'] {
        top: -.6875em;
        left: 1.875em;
        -webkit-transform: rotate(-45deg);
                transform: rotate(-45deg);
        -webkit-transform-origin: 0 3.75em;
                transform-origin: 0 3.75em;
        border-radius: 0 7.5em 7.5em 0; }
    .swal2-icon.swal2-success .swal2-success-ring {
      position: absolute;
      top: -.25em;
      left: -.25em;
      width: 100%;
      height: 100%;
      border: 0.25em solid rgba(165, 220, 134, 0.3);
      border-radius: 50%;
      z-index: 2;
      box-sizing: content-box; }
    .swal2-icon.swal2-success .swal2-success-fix {
      position: absolute;
      top: .5em;
      left: 1.625em;
      width: .4375em;
      height: 5.625em;
      -webkit-transform: rotate(-45deg);
              transform: rotate(-45deg);
      z-index: 1; }
    .swal2-icon.swal2-success [class^='swal2-success-line'] {
      display: block;
      position: absolute;
      height: .3125em;
      border-radius: .125em;
      background-color: #a5dc86;
      z-index: 2; }
      .swal2-icon.swal2-success [class^='swal2-success-line'][class$='tip'] {
        top: 2.875em;
        left: .875em;
        width: 1.5625em;
        -webkit-transform: rotate(45deg);
                transform: rotate(45deg); }
      .swal2-icon.swal2-success [class^='swal2-success-line'][class$='long'] {
        top: 2.375em;
        right: .5em;
        width: 2.9375em;
        -webkit-transform: rotate(-45deg);
                transform: rotate(-45deg); }

.swal2-progresssteps {
  align-items: center;
  margin: 0 0 1.25em;
  padding: 0;
  font-weight: 600; }
  .swal2-progresssteps li {
    display: inline-block;
    position: relative; }
  .swal2-progresssteps .swal2-progresscircle {
    width: 2em;
    height: 2em;
    border-radius: 2em;
    background: #3085d6;
    color: #fff;
    line-height: 2em;
    text-align: center;
    z-index: 20; }
    .swal2-progresssteps .swal2-progresscircle:first-child {
      margin-left: 0; }
    .swal2-progresssteps .swal2-progresscircle:last-child {
      margin-right: 0; }
    .swal2-progresssteps .swal2-progresscircle.swal2-activeprogressstep {
      background: #3085d6; }
      .swal2-progresssteps .swal2-progresscircle.swal2-activeprogressstep ~ .swal2-progresscircle {
        background: #add8e6; }
      .swal2-progresssteps .swal2-progresscircle.swal2-activeprogressstep ~ .swal2-progressline {
        background: #add8e6; }
  .swal2-progresssteps .swal2-progressline {
    width: 2.5em;
    height: .4em;
    margin: 0 -1px;
    background: #3085d6;
    z-index: 10; }

[class^='swal2'] {
  -webkit-tap-highlight-color: transparent; }

.swal2-show {
  -webkit-animation: swal2-show 0.3s;
          animation: swal2-show 0.3s; }
  .swal2-show.swal2-noanimation {
    -webkit-animation: none;
            animation: none; }

.swal2-hide {
  -webkit-animation: swal2-hide 0.15s forwards;
          animation: swal2-hide 0.15s forwards; }
  .swal2-hide.swal2-noanimation {
    -webkit-animation: none;
            animation: none; }

[dir='rtl'] .swal2-close {
  right: auto;
  left: 0; }

.swal2-animate-success-icon .swal2-success-line-tip {
  -webkit-animation: swal2-animate-success-line-tip 0.75s;
          animation: swal2-animate-success-line-tip 0.75s; }

.swal2-animate-success-icon .swal2-success-line-long {
  -webkit-animation: swal2-animate-success-line-long 0.75s;
          animation: swal2-animate-success-line-long 0.75s; }

.swal2-animate-success-icon .swal2-success-circular-line-right {
  -webkit-animation: swal2-rotate-success-circular-line 4.25s ease-in;
          animation: swal2-rotate-success-circular-line 4.25s ease-in; }

.swal2-animate-error-icon {
  -webkit-animation: swal2-animate-error-icon 0.5s;
          animation: swal2-animate-error-icon 0.5s; }
  .swal2-animate-error-icon .swal2-x-mark {
    -webkit-animation: swal2-animate-error-x-mark 0.5s;
            animation: swal2-animate-error-x-mark 0.5s; }

@-webkit-keyframes swal2-rotate-loading {
  0% {
    -webkit-transform: rotate(0deg);
            transform: rotate(0deg); }
  100% {
    -webkit-transform: rotate(360deg);
            transform: rotate(360deg); } }

@keyframes swal2-rotate-loading {
  0% {
    -webkit-transform: rotate(0deg);
            transform: rotate(0deg); }
  100% {
    -webkit-transform: rotate(360deg);
            transform: rotate(360deg); } }</style><style>
  .vt-augment {
    position: relative;
    display: flex;
    justify-content: center;
    align-items: center;
  }
  .vt-augment.drawer {
    display: none;
    width: 700px;
    background: white;
    border: 1px solid #e6e6e6;
    text-align: left;
    z-index: 102;
    position: fixed;
    right: 0;
    top: 0;
    height: 100vh;
    box-shadow: -4px 5px 8px -3px rgba(17, 17, 17, .16);
    animation: slideToRight 0.5s 1 forwards;
    transform: translateX(100vw);
  }
  .vt-augment.drawer[opened] {
    display: flex;
    animation: slideFromRight 0.2s 1 forwards;
  }
  .vt-augment > .spinner {
    position: absolute;
    z-index: 199;
    top: calc(50% - 50px);
    left: calc(50% - 50px);
    border: 8px solid rgba(0, 0, 0, 0.2);
    border-left-color: white;
    border-radius: 50%;
    width: 50px;
    height: 50px;
    animation: spin 1.2s linear infinite;
  }
  @keyframes spin {
    to { transform: rotate(360deg); }
  }
  @keyframes slideFromRight {
    0% {
      transform: translateX(100vw);
    }
    100% {
      transform: translateX(0);
    }
  }
  @keyframes slideToRight {
    100% {
      transform: translateX(100vw);
      display: none;
    }
  }
  @media screen and (max-width: 700px) {
    .vt-augment.drawer {
      width: 100%;
    }
  }
</style></head>
<body data-new-gr-c-s-check-loaded="14.1146.0" data-gr-ext-installed=""><div class="center">
<table>
<tbody><tr class="h"><td>
<a href="http://www.php.net/"><img border="0" src="data:image/png;base64,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" alt="PHP logo"></a><h1 class="p">PHP Version 7.4.3-4ubuntu2.18</h1>
</td></tr>
</tbody></table>
<table>
<tbody><tr><td class="e">System </td><td class="v">Linux 512e79b087c5 5.4.0-122-generic #138-Ubuntu SMP Wed Jun 22 15:00:31 UTC 2022 x86_64 </td></tr>
<tr><td class="e">Build Date </td><td class="v">Feb 23 2023 12:43:23 </td></tr>
<tr><td class="e">Server API </td><td class="v">Apache 2.0 Handler </td></tr>
<tr><td class="e">Virtual Directory Support </td><td class="v">disabled </td></tr>
<tr><td class="e">Configuration File (php.ini) Path </td><td class="v">/etc/php/7.4/apache2 </td></tr>
<tr><td class="e">Loaded Configuration File </td><td class="v">/etc/php/7.4/apache2/php.ini </td></tr>
<tr><td class="e">Scan this dir for additional .ini files </td><td class="v">/etc/php/7.4/apache2/conf.d </td></tr>
<tr><td class="e">Additional .ini files parsed </td><td class="v">/etc/php/7.4/apache2/conf.d/10-mysqlnd.ini,
/etc/php/7.4/apache2/conf.d/10-opcache.ini,
/etc/php/7.4/apache2/conf.d/10-pdo.ini,
/etc/php/7.4/apache2/conf.d/15-xml.ini,
/etc/php/7.4/apache2/conf.d/20-apcu.ini,
/etc/php/7.4/apache2/conf.d/20-calendar.ini,
/etc/php/7.4/apache2/conf.d/20-ctype.ini,
/etc/php/7.4/apache2/conf.d/20-curl.ini,
/etc/php/7.4/apache2/conf.d/20-dom.ini,
/etc/php/7.4/apache2/conf.d/20-exif.ini,
/etc/php/7.4/apache2/conf.d/20-ffi.ini,
/etc/php/7.4/apache2/conf.d/20-fileinfo.ini,
/etc/php/7.4/apache2/conf.d/20-ftp.ini,
/etc/php/7.4/apache2/conf.d/20-gd.ini,
/etc/php/7.4/apache2/conf.d/20-gettext.ini,
/etc/php/7.4/apache2/conf.d/20-gmp.ini,
/etc/php/7.4/apache2/conf.d/20-iconv.ini,
/etc/php/7.4/apache2/conf.d/20-igbinary.ini,
/etc/php/7.4/apache2/conf.d/20-imagick.ini,
/etc/php/7.4/apache2/conf.d/20-intl.ini,
/etc/php/7.4/apache2/conf.d/20-json.ini,
/etc/php/7.4/apache2/conf.d/20-ldap.ini,
/etc/php/7.4/apache2/conf.d/20-mbstring.ini,
/etc/php/7.4/apache2/conf.d/20-mysqli.ini,
/etc/php/7.4/apache2/conf.d/20-pdo_mysql.ini,
/etc/php/7.4/apache2/conf.d/20-pdo_pgsql.ini,
/etc/php/7.4/apache2/conf.d/20-pdo_sqlite.ini,
/etc/php/7.4/apache2/conf.d/20-pgsql.ini,
/etc/php/7.4/apache2/conf.d/20-phar.ini,
/etc/php/7.4/apache2/conf.d/20-posix.ini,
/etc/php/7.4/apache2/conf.d/20-readline.ini,
/etc/php/7.4/apache2/conf.d/20-redis.ini,
/etc/php/7.4/apache2/conf.d/20-shmop.ini,
/etc/php/7.4/apache2/conf.d/20-simplexml.ini,
/etc/php/7.4/apache2/conf.d/20-smbclient.ini,
/etc/php/7.4/apache2/conf.d/20-soap.ini,
/etc/php/7.4/apache2/conf.d/20-sockets.ini,
/etc/php/7.4/apache2/conf.d/20-sqlite3.ini,
/etc/php/7.4/apache2/conf.d/20-sysvmsg.ini,
/etc/php/7.4/apache2/conf.d/20-sysvsem.ini,
/etc/php/7.4/apache2/conf.d/20-sysvshm.ini,
/etc/php/7.4/apache2/conf.d/20-tokenizer.ini,
/etc/php/7.4/apache2/conf.d/20-xmlreader.ini,
/etc/php/7.4/apache2/conf.d/20-xmlwriter.ini,
/etc/php/7.4/apache2/conf.d/20-xsl.ini,
/etc/php/7.4/apache2/conf.d/20-zip.ini,
/etc/php/7.4/apache2/conf.d/25-apcu_bc.ini,
/etc/php/7.4/apache2/conf.d/99-owncloud.ini
 </td></tr>
<tr><td class="e">PHP API </td><td class="v">20190902 </td></tr>
<tr><td class="e">PHP Extension </td><td class="v">20190902 </td></tr>
<tr><td class="e">Zend Extension </td><td class="v">320190902 </td></tr>
<tr><td class="e">Zend Extension Build </td><td class="v">API320190902,NTS </td></tr>
<tr><td class="e">PHP Extension Build </td><td class="v">API20190902,NTS </td></tr>
<tr><td class="e">Debug Build </td><td class="v">no </td></tr>
<tr><td class="e">Thread Safety </td><td class="v">disabled </td></tr>
<tr><td class="e">Zend Signal Handling </td><td class="v">enabled </td></tr>
<tr><td class="e">Zend Memory Manager </td><td class="v">enabled </td></tr>
<tr><td class="e">Zend Multibyte Support </td><td class="v">provided by mbstring </td></tr>
<tr><td class="e">IPv6 Support </td><td class="v">enabled </td></tr>
<tr><td class="e">DTrace Support </td><td class="v">available, disabled </td></tr>
<tr><td class="e">Registered PHP Streams</td><td class="v">https, ftps, compress.zlib, php, file, glob, data, http, ftp, smb, zip, phar</td></tr>
<tr><td class="e">Registered Stream Socket Transports</td><td class="v">tcp, udp, unix, udg, ssl, tls, tlsv1.0, tlsv1.1, tlsv1.2, tlsv1.3</td></tr>
<tr><td class="e">Registered Stream Filters</td><td class="v">zlib.*, string.rot13, string.toupper, string.tolower, string.strip_tags, convert.*, consumed, dechunk, convert.iconv.*</td></tr>
</tbody></table>
<table>
<tbody><tr class="v"><td>
<a href="http://www.zend.com/"><img border="0" src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAPoAAAAvCAYAAADKH9ehAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAEWJJREFUeNrsXQl0VNUZvjNJSAgEAxHCGsNitSBFxB1l0boUW1pp3VAUrKLWKgUPUlEB13K0Yq1alaXWuh5EadWK1F0s1gJaoaCgQDRKBBJDVhKSzPR+zPfg5vLevCUzmZnwvnP+k8ybN3fevfff73/vBAJTHxc+khL5kr6T1ODk5nAgTRTWloghFVtEg/zfh2PkSvq9pJGSKiX9SdKittbJoD/PSYkrJD0vKeB4IsNNotfuUtHk/CM+IvijpF9KGiDpGEkLJZ3lC7qPeKKTpD9IWiDpUOfWPCi61ZeLvD2VIhTwp9QlTjK5NsIXdB/xxHmSpvD/OucWPSAyQw2+LfeG1SbXVra1Tqb785xUaNdMel0g7Iu5V1zPv6dJqpD0kKR/+ILuI55o8oeg1bFT0kWSOkraQxK+oPvw0TZR3ZY758foyQXf//ZxUFh0Q/GEfNf9gHkaJ6m7pHJJSyTt9tnXhxtBR2EGlnHCMbZMaHuHzX19JZ0u6VRJh0k6hM+BpMjnklZIelPSNhff3V5StkNlEWBMFm+3LcC+BW3GuZP2GvfmiEiCCMUzxZIKRGSt9zeML/fdGAW9JB3O8c6SlMZ+b5f0qaQiF7EpnieXY1auvZfG7zhSUk8RSS428F7M5xfsh1eAV/vxOzoq16sklZBqbdpo5H2qDPRQXoP3Ki0+20FSFyrZUgt+Rt/7KH2vZb8/t/iMG2Sy/0dI6sbvgHGoV8a3xErQb5Q0iTfHCplkzlkW7w+VNF3ST7QJUzFK0pVkDFiw+yV95uC7r5Z0k3CW2ApwIkrJ9B9IelfSh2SIlqC/pDFUZAVk0rQoMhk2GYswx+AtWvMKPtcyEckW37pPwsIHNAuBniDpYhEpBMmJwvibJL0gIlVh39r0C8UlczkXQ/mM6OtEzuf3RfPVAxUY47f5PStcGKPxpOMldbbxiBptPMavJX1PuQ/P/olyz12S7rD4PLyqBTQ8gyXVSOot6VK+dxR53wyl7POjkv7pkpcwpleJSCHP4eQjM0BB/ZuG4Hl9EO8mQx4ZQ0FfL+k+k+t4wNlULpkO24IGnSzpQklzKPDRAMvZ1eXz9uXfH/Pvx5Ie44C5zYQXUgDPj6LEnMCQ3AFkjjupjGF9/kJmxPw1oiquz+6dalXcCRSmYxwK0kDSRI71azb3Y+6GiMi6P/5ey3F3YpExjxdQoG61uX8gBetkh2OWFkUIVGUT1pS9yosZNu1nkl8uZH+mikhxkx1wz7mkB0WkXsKJFw1ZuSWKotY9wjNJS6mUy41JK5P0c2qCnBgIeQWZvEK7Dnf6WUljTT5TS7d0KwezkJShdWIeGeuKKJo7FktUQylcl0i6RtL/HH4OjP+wB0UTLTGHfubRDWyi1g7SaoZQ495z9w7RpaHKqHEfLeklEyWzk+7dl3TTu1KQCpV7+pBB4IWstFFAgvOpJnTL6DoW0xPbw3k/nIYkW+kbmHeXhUEABklazrBDBdzTDfyuBo5DPq1eoUk7ZbSk70l6n3MZjUdCDpQvMF/rezn7/hX7Xs8wsj/7rsrWdQxnZtrwwENUosJkDDZxTjOUkEH1ds6lzJyDZzGScRsonGNcMCIG+WgRKTRQ8Su2p7uRi/mlKjZKekREChS2KIOcTvfqp3RZDlM+cxnfv8Thc75Pt8kqo92VzNTbxBqcQlceivAdByHDIxbvFTMOLovyHAGGK3qc/jJDoDc4hpjABzBm4UAglBFqEAOqt8mB29ss4uJnNCHfSK/tVZMYEfMykt7Bcco1eDLDHCT8gmzzRdLHZL6wRSgzg6GIgVl8Xj2uhPA+oQn53yTdK2mVMC8NzuJ8zaSyM/ApxyzWCFJRvUQ3eQ29BTNFcRgt+FTl2g30zDZZtD/ZRMifE5ES6Y9MxqAHQ7XZikI9nd97j5p1f83GZTPr6Crt2sOcOB1zTYT8HrqjVRZx4wbSAt47SXn/YsZV9zp4zuvJgNGQRaszmoN1rBY6IH4dHiVHcA5dZd2zeIbPv8ZBkghYTQFTx/h1WvSz6c3kM5ewGG8Prvxc5DZWS2u+dypnM5Y3sIJMXmbxfXW0misZN56oxITnWsyl2fg+6+C+zWTefMWr68RwaYF271htHBZqCsKqL28wB/ACjYShrE9nUjfWmEU33A7woqbR4k5UlNk4yoYOzOHvtGs30KO1QgnlZC2VohGOIGn7WEvW0ZdoMeCHfBgdo8X++m3V+s2wEHKzJMblJom92+ne2SHDwT1gknUispPpJLrrVZqwLxTmy5F5jOdVS72F/b6UwlbrcEytrD00+a8l/ZUM82jEZd8peu8uNYS8JxNWqis5IYqQCy1rPUULh8Y7fOYal3zzmPb6aJN7zlf+32bBV9ESclNE85WUX4j4oNbl/fM1b2eoxX3jyXNqiDTP4Xe8Rm9ItfSjvAr6DM0d+o5MXW/CuHO0a7eZTLYT3KF9LktYZ/WdCI+IkoV+lFZ6l3J9OF14HdM0F3MrhXxFjJmqhh5FBera24XqxaCqL0UosK97Z2ku+yJaEqf4D62ByoROcjZuN78Xaa9zTBSzKvxvC+vlrmgWVPU2h4j4FCO5lZ+vNBnpYHHfOOX/PfR83eApTaGM8CLop5l88WSLWAOu4AiNme5owcBO1xhlLGO/eGAFkyYqrtFe5zKzqU7KBE5o/BAIiv7VJSK7qV4GhEF1XtSk0YseWl6lWYI+cXj6pigJLkH3Vk0qfebxe4q0JGOGSDxCWn/Nchk9qJgMfGKS87LDes1IHeVW0LszgaC6sPMYE5lBt4CzRcuy4lVMLKlWfWwcJ+YpxtcGjtOYfzRjTgNIlv0rnpyCveeHNFSJ/jUlonH/3nNYqyOU28qYhHOLbzVPqFc81JQDKxnQ5twLdmjfmQzlxU6eoZ/mma3y8D3VonlhUr6bElhMwJ81RseSxW+jfOYULdYGAw5s4WBtpeU0ijKwxnp/HCfn70piCNlMFEUU8/WpmnZe1Bq80r96m5yMkIwx9nnNHTWFs114q0ArM1HsiUY7j5/rKFIThdrrzR7agHyoy9vd3Ag64uEfKa+xjIKlLqtTUBB7FWgJrQ9joFl1d2cQ2wzHaeDXa6/ztO9Wx+OT+FrzSAKuV12ptOZp+ljnaVawk8uxDpnMZXYCGB3PXqe5sl7QQ5ubhhQR9B4mQpvjIR+gJgrbOxV0rK/rVUyXmyRWdI2a2YLEhVP3BwmN9sJ9BtQpKkxiSDOrUeUhaeQaPevKzKQ3oIVTSGatcynoRl29sIkh440a8pURNoz00Ab4Ts1obxCps1FKl8k5IpKbcmsgu6nz6ETQC+iSqoKKOPmVJBmYnDjHX4EozB9s7TgwykkyYS13URAHpmstYIloOP/HEi6Wx5a4+DwSpH2V18tTyHUPm3iQeS1s09ai4/0ntVgNRQmzHTRulGwaQNnei3FgHqPcMBEJlXrNioAaE8AcupKBd7ElBu1uTxCzg+dmKB4TahiQNX/OxssAb00Uzdeci4S3FYhEQdfkWCrc1cI2K+2EDhsP1OUxZGUnOWTmcgphV0UgZ4jUR1hLlBiuJfqJpb61CXimOrq8RqiEeu6TU3iMwdzYgWhUnWHDDKr0ptLar6USqmOfYYiGMMTUN/KgziGVTo+pNJHBBfF0zVAQc6N2DUL+tcO2Yc1Rk2ss+yBmOko43yCSCljJXAWA7PD4eAt6MBy2yiNACRvVVN05t40pPLYPsT+zlRDpOLG/Jt8OSGKhmnBpivV7q/Y6JkucVgkyWKb52rVZwl0tvNDi+AzRvKjfK1Dnjvpd1FhPEc1LBVsbqENXN35cFaPY2BIVGdlWYZKqgPPj/RythNtpcNycpoOxwAae0bGwhAkAQg01cfiDWDRqZtHhCqFQ5FAtOXKXh/Yh6Ci2N5YMUDW2SHg/N3scn02N++cnMIZCBdwS9gtApRxqDc6OlzWtSrdc8cJGlzP5fzZDri1tQNixISWL/5fSQvcVzfe/wzXfSG8Kuw03pHB/t5KMik+EYJ1EC1d0zCw6fofqRI2ZJwpvyxN4uPs0q/6UR2szyESobxatf3aa7jvfrT0DGPNpYV3H3CI0BYLGllQdy7TX14rUP/zzDHpuRp0EPLnJvH68Qij/RXnyIyku5Ea+5S3NO7s01q77eMY1qqY8T7Qs+4qtq+o2UWhjZO6HuWhjJBlZXWbAHvbFSTAxqMW+RbuG3VfviAP36tshujINh6Tr3kE0BNMl5x8Qq6+mVTdwrMlzpRrGaGPzVpw9NDNFngjoFZZzRCS/FRPXHRZT31X2MgfYTQYX1WE1moaaQJfKEFTs/camkXnUwt9YtNWPiuc67VmRlb0yiRgS/cAe7is0QXuTAm9kikM2DNc5OkeGRaMU8tq0TJHbUCOtezMeRfITiSv1PLLbGE5gb/NOB/1AuR1KlLETDltidyR4XIPasyEnc6eIbRa9kfNifFeXJOAnVJBiKfFCvobcLKccLHWojHJpIPH3iXQlpoNLrdcH44sucvmQOHHjZ9rDrGdbixVmbk/XGy4mtiKuoQDjmQpFJLs6wuSZvqKmL0ky6zOZLry+420UKUaue5ooyeqy9+iopgM989cp1Dcp16bSU1tOJbyFyjedTID5wOk6OAUFFXUDKFRLkmBM3xH7fzIJwPLsxexDMWP2b8g38DqN45ywCuH0VNuv+XmjwOYCjtUakbg6AkGlNoQGBMB5A9g8hh2g7zFE2U4F35FxfHfmwwbxcz3Yl32C/oAwPwDAS6UXdpOhXPZ27Trc9R/SLTla0zzGoXl2QAexnLVZJB/CZMpV7HthfL4lJIrb54u+tdv3/rCiSbw+k88yM9ZxXgKwlHmZycq13iSr0KeMHmUZw6r1VICrLT4D5fy4wq/5DAvfjaWC9oAd9KxwTNUJynUjL+EqpwSTME1zOWMBuIxmZ7p9RCsNq+NmdxW09I1MdNkJeYZNHsIt0qKEO2Z4kvmHadS+Xqv2cqzc93rpuhdl54tg2DISuJljBW3uZjMHrAPqHOYK6zPIM23G2+14Rts4cyLbdxo3Y667UskOo/W/m/PwRhQBwZFkT2vXzDbTtLMZCyfP1155bbfDrpjKZoYH41bO+d97jmEgMPVxFMF0iHESIkiNtDhKuwV058cw0dBZNP+lFsSU/6VWf0E4P/x+IF2eJnokr4uW/2jAKPYjjRb7Cxef70c3qsCl0im1Gj/Uu2eF6sWo0rUiTQq7zS+pYjywnXYwcyOZfI4mKgHj9N2ttHqbRfSlQXhjw5XXy4S7ZbzOovkxVRsphHp8ia3HlyleZS1zHcvoVrdjuNFdEe7edGHzSbpSria/WZ3+cxYV5DCx/4w7FUfyfTW0WO+i7x2YrzKUXZFw/sut+OxJDGkHUxEZPwgCquQcIgxZR9oXekDQk8FF60bqwocupaIoEz6EmaC3C+0Ro6Wgp4eb2tpPJqN+4xXFXQ3TfUfCc5PDNnLZDpLIV1NADKyjZa87mHgmWX57bYdIfIY3pdCGf43xQUXI62kBn3fZxi4SPC8crIjDQ4yzFAaz/XcPJn7xf03VRzIB5Z7qCbBzPQi5jga2E9bCD+ELug8ficEZCk/Cmj8Ro3aLtLxDR1/QffhIHNRTUZCf+S5G7SJBp2b7G31B9+EjcVAFEInZQ2LU7jiN1zf4gu7DR+KwTvkfO9bGx6BNnEQ8XXmN5cT3fEH34SNxwN4A9dgknIEwyWNbeRTwV7WYHBVwFQfbwKb7vOUjiYAiKVT1PczXqCLD/n5UbuLcNxTKoCgExSFNmsFCHI6iJBQFnUbqqbWPHyFceDAOrC/oPpIN+FVaVLrNUa6dLPbvoEQdO4pd1OUylBVkCutsOkqosbNvwcE6qL6g+0hG3MY4ejots1pT3kE4P9QDdfuLKeDfHswD6gu6j2TF2yQcLoqEGurre9EdP1QTfmxJRdn0NlrvD+jmY69Egz+UQvxfgAEALJ4EcRDa/toAAAAASUVORK5CYII=" alt="Zend logo"></a>
This program makes use of the Zend Scripting Language Engine:<br>Zend&nbsp;Engine&nbsp;v3.4.0,&nbsp;Copyright&nbsp;(c)&nbsp;Zend&nbsp;Technologies<br>&nbsp;&nbsp;&nbsp;&nbsp;with&nbsp;Zend&nbsp;OPcache&nbsp;v7.4.3-4ubuntu2.18,&nbsp;Copyright&nbsp;(c),&nbsp;by&nbsp;Zend&nbsp;Technologies<br></td></tr>
</tbody></table>
<hr>
<h1>Configuration</h1>
<h2><a name="module_apache2handler">apache2handler</a></h2>
<table>
<tbody><tr><td class="e">Apache Version </td><td class="v">Apache </td></tr>
<tr><td class="e">Apache API Version </td><td class="v">20120211 </td></tr>
<tr><td class="e">Server Administrator </td><td class="v">webmaster@localhost </td></tr>
<tr><td class="e">Hostname:Port </td><td class="v">localhost:8080 </td></tr>
<tr><td class="e">User/Group </td><td class="v">www-data(33)/33 </td></tr>
<tr><td class="e">Max Requests </td><td class="v">Per Child: 0 - Keep Alive: on - Max Per Connection: 100 </td></tr>
<tr><td class="e">Timeouts </td><td class="v">Connection: 300 - Keep-Alive: 5 </td></tr>
<tr><td class="e">Virtual Server </td><td class="v">Yes </td></tr>
<tr><td class="e">Server Root </td><td class="v">/etc/apache2 </td></tr>
<tr><td class="e">Loaded Modules </td><td class="v">core mod_so mod_watchdog http_core mod_log_config mod_logio mod_version mod_unixd mod_access_compat mod_alias mod_auth_basic mod_authn_core mod_authn_file mod_authz_core mod_authz_host mod_authz_user mod_autoindex mod_deflate mod_dir mod_env mod_expires mod_filter mod_headers mod_mime prefork mod_negotiation mod_php7 mod_remoteip mod_reqtimeout mod_rewrite mod_setenvif mod_status </td></tr>
</tbody></table>
<table>
<tbody><tr class="h"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>
<tr><td class="e">engine</td><td class="v">1</td><td class="v">1</td></tr>
<tr><td class="e">last_modified</td><td class="v">0</td><td class="v">0</td></tr>
<tr><td class="e">xbithack</td><td class="v">0</td><td class="v">0</td></tr>
</tbody></table>
<h2>Apache Environment</h2>
<table>
<tbody><tr class="h"><th>Variable</th><th>Value</th></tr>
<tr><td class="e">HTTP_AUTHORIZATION </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">modHeadersAvailable </td><td class="v">true </td></tr>
<tr><td class="e">htaccessWorking </td><td class="v">true </td></tr>
<tr><td class="e">front_controller_active </td><td class="v">true </td></tr>
<tr><td class="e">HTTP_HOST </td><td class="v">badowncloud:8080 </td></tr>
<tr><td class="e">HTTP_CONNECTION </td><td class="v">keep-alive </td></tr>
<tr><td class="e">HTTP_DNT </td><td class="v">1 </td></tr>
<tr><td class="e">HTTP_UPGRADE_INSECURE_REQUESTS </td><td class="v">1 </td></tr>
<tr><td class="e">HTTP_USER_AGENT </td><td class="v">Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 </td></tr>
<tr><td class="e">HTTP_ACCEPT </td><td class="v">text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7 </td></tr>
<tr><td class="e">HTTP_ACCEPT_ENCODING </td><td class="v">gzip, deflate </td></tr>
<tr><td class="e">HTTP_ACCEPT_LANGUAGE </td><td class="v">en-US,en;q=0.9 </td></tr>
<tr><td class="e">HTTP_COOKIE </td><td class="v">oce6x9uqffor=vi3opkotft2oo209cj7j03dvmi; oc_sessionPassphrase=LT7Az1LZ87Fg5MlFkb0811zpzhYGsfike%2F2rfSrL8fBxFOniCzbhqowdPbg9V8GmcF9H7duEscB81sPKVdKOQokR4MatJDdxs4eHWrdP%2BkAIena7S%2B4Y2%2BJLQN%2BX02I9 </td></tr>
<tr><td class="e">PATH </td><td class="v">/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin </td></tr>
<tr><td class="e">SERVER_SIGNATURE </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">SERVER_SOFTWARE </td><td class="v">Apache </td></tr>
<tr><td class="e">SERVER_NAME </td><td class="v">badowncloud </td></tr>
<tr><td class="e">SERVER_ADDR </td><td class="v">172.18.0.4 </td></tr>
<tr><td class="e">SERVER_PORT </td><td class="v">8080 </td></tr>
<tr><td class="e">REMOTE_ADDR </td><td class="v">192.168.56.1 </td></tr>
<tr><td class="e">DOCUMENT_ROOT </td><td class="v">/var/www/owncloud </td></tr>
<tr><td class="e">REQUEST_SCHEME </td><td class="v">http </td></tr>
<tr><td class="e">CONTEXT_PREFIX </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">CONTEXT_DOCUMENT_ROOT </td><td class="v">/var/www/owncloud </td></tr>
<tr><td class="e">SERVER_ADMIN </td><td class="v">webmaster@localhost </td></tr>
<tr><td class="e">SCRIPT_FILENAME </td><td class="v">/var/www/owncloud/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php </td></tr>
<tr><td class="e">REMOTE_PORT </td><td class="v">65495 </td></tr>
<tr><td class="e">GATEWAY_INTERFACE </td><td class="v">CGI/1.1 </td></tr>
<tr><td class="e">SERVER_PROTOCOL </td><td class="v">HTTP/1.1 </td></tr>
<tr><td class="e">REQUEST_METHOD </td><td class="v">GET </td></tr>
<tr><td class="e">QUERY_STRING </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">REQUEST_URI </td><td class="v">//apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php/ </td></tr>
<tr><td class="e">SCRIPT_NAME </td><td class="v">/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php </td></tr>
<tr><td class="e">PATH_INFO </td><td class="v">/ </td></tr>
<tr><td class="e">PATH_TRANSLATED </td><td class="v">/var/www/owncloud/index.php </td></tr>
</tbody></table>
<h2>HTTP Headers Information</h2>
<table>
<tbody><tr class="h"><th colspan="2">HTTP Request Headers</th></tr>
<tr><td class="e">HTTP Request </td><td class="v">GET //apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php/ HTTP/1.1 </td></tr>
<tr><td class="e">Host </td><td class="v">badowncloud:8080 </td></tr>
<tr><td class="e">Connection </td><td class="v">keep-alive </td></tr>
<tr><td class="e">DNT </td><td class="v">1 </td></tr>
<tr><td class="e">Upgrade-Insecure-Requests </td><td class="v">1 </td></tr>
<tr><td class="e">User-Agent </td><td class="v">Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 </td></tr>
<tr><td class="e">Accept </td><td class="v">text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7 </td></tr>
<tr><td class="e">Accept-Encoding </td><td class="v">gzip, deflate </td></tr>
<tr><td class="e">Accept-Language </td><td class="v">en-US,en;q=0.9 </td></tr>
<tr><td class="e">Cookie </td><td class="v">oce6x9uqffor=vi3opkotft2oo209cj7j03dvmi; oc_sessionPassphrase=LT7Az1LZ87Fg5MlFkb0811zpzhYGsfike%2F2rfSrL8fBxFOniCzbhqowdPbg9V8GmcF9H7duEscB81sPKVdKOQokR4MatJDdxs4eHWrdP%2BkAIena7S%2B4Y2%2BJLQN%2BX02I9 </td></tr>
<tr class="h"><th colspan="2">HTTP Response Headers</th></tr>
</tbody></table>
<h2><a name="module_apc">apc</a></h2>
<table>
<tbody><tr><td class="e">APC Compatibility </td><td class="v">1.0.5 </td></tr>
</tbody></table>
<h2><a name="module_apcu">apcu</a></h2>
<table>
<tbody><tr><td class="e">APCu Support </td><td class="v">Enabled </td></tr>
<tr><td class="e">Version </td><td class="v">5.1.18 </td></tr>
<tr><td class="e">APCu Debugging </td><td class="v">Disabled </td></tr>
<tr><td class="e">MMAP Support </td><td class="v">Enabled </td></tr>
<tr><td class="e">MMAP File Mask </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">Serialization Support </td><td class="v">php, igbinary </td></tr>
<tr><td class="e">Build Date </td><td class="v">Feb 25 2020 01:43:03 </td></tr>
</tbody></table>
<table>
<tbody><tr class="h"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>
<tr><td class="e">apc.coredump_unmap</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">apc.enable_cli</td><td class="v">On</td><td class="v">On</td></tr>
<tr><td class="e">apc.enabled</td><td class="v">On</td><td class="v">On</td></tr>
<tr><td class="e">apc.entries_hint</td><td class="v">4096</td><td class="v">4096</td></tr>
<tr><td class="e">apc.gc_ttl</td><td class="v">3600</td><td class="v">3600</td></tr>
<tr><td class="e">apc.mmap_file_mask</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">apc.preload_path</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">apc.serializer</td><td class="v">php</td><td class="v">php</td></tr>
<tr><td class="e">apc.shm_segments</td><td class="v">1</td><td class="v">1</td></tr>
<tr><td class="e">apc.shm_size</td><td class="v">32M</td><td class="v">32M</td></tr>
<tr><td class="e">apc.slam_defense</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">apc.smart</td><td class="v">0</td><td class="v">0</td></tr>
<tr><td class="e">apc.ttl</td><td class="v">0</td><td class="v">0</td></tr>
<tr><td class="e">apc.use_request_time</td><td class="v">On</td><td class="v">On</td></tr>
</tbody></table>
<h2><a name="module_calendar">calendar</a></h2>
<table>
<tbody><tr><td class="e">Calendar support </td><td class="v">enabled </td></tr>
</tbody></table>
<h2><a name="module_core">Core</a></h2>
<table>
<tbody><tr><td class="e">PHP Version </td><td class="v">7.4.3-4ubuntu2.18 </td></tr>
</tbody></table>
<table>
<tbody><tr class="h"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>
<tr><td class="e">allow_url_fopen</td><td class="v">On</td><td class="v">On</td></tr>
<tr><td class="e">allow_url_include</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">arg_separator.input</td><td class="v">&amp;</td><td class="v">&amp;</td></tr>
<tr><td class="e">arg_separator.output</td><td class="v">&amp;</td><td class="v">&amp;</td></tr>
<tr><td class="e">auto_append_file</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">auto_globals_jit</td><td class="v">On</td><td class="v">On</td></tr>
<tr><td class="e">auto_prepend_file</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">browscap</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">default_charset</td><td class="v">UTF-8</td><td class="v">UTF-8</td></tr>
<tr><td class="e">default_mimetype</td><td class="v">text/html</td><td class="v">text/html</td></tr>
<tr><td class="e">disable_classes</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">disable_functions</td><td class="v">pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,pcntl_unshare,</td><td class="v">pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,pcntl_unshare,</td></tr>
<tr><td class="e">display_errors</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">display_startup_errors</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">doc_root</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">docref_ext</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">docref_root</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">enable_dl</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">enable_post_data_reading</td><td class="v">On</td><td class="v">On</td></tr>
<tr><td class="e">error_append_string</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">error_log</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">error_prepend_string</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">error_reporting</td><td class="v">22527</td><td class="v">22527</td></tr>
<tr><td class="e">expose_php</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">extension_dir</td><td class="v">/usr/lib/php/20190902</td><td class="v">/usr/lib/php/20190902</td></tr>
<tr><td class="e">file_uploads</td><td class="v">On</td><td class="v">On</td></tr>
<tr><td class="e">hard_timeout</td><td class="v">2</td><td class="v">2</td></tr>
<tr><td class="e">highlight.comment</td><td class="v"><font style="color: #FF8000">#FF8000</font></td><td class="v"><font style="color: #FF8000">#FF8000</font></td></tr>
<tr><td class="e">highlight.default</td><td class="v"><font style="color: #0000BB">#0000BB</font></td><td class="v"><font style="color: #0000BB">#0000BB</font></td></tr>
<tr><td class="e">highlight.html</td><td class="v"><font style="color: #000000">#000000</font></td><td class="v"><font style="color: #000000">#000000</font></td></tr>
<tr><td class="e">highlight.keyword</td><td class="v"><font style="color: #007700">#007700</font></td><td class="v"><font style="color: #007700">#007700</font></td></tr>
<tr><td class="e">highlight.string</td><td class="v"><font style="color: #DD0000">#DD0000</font></td><td class="v"><font style="color: #DD0000">#DD0000</font></td></tr>
<tr><td class="e">html_errors</td><td class="v">On</td><td class="v">On</td></tr>
<tr><td class="e">ignore_repeated_errors</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">ignore_repeated_source</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">ignore_user_abort</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">implicit_flush</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">include_path</td><td class="v">.:/usr/share/php</td><td class="v">.:/usr/share/php</td></tr>
<tr><td class="e">input_encoding</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">internal_encoding</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">log_errors</td><td class="v">On</td><td class="v">On</td></tr>
<tr><td class="e">log_errors_max_len</td><td class="v">1024</td><td class="v">1024</td></tr>
<tr><td class="e">mail.add_x_header</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">mail.force_extra_parameters</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">mail.log</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">max_execution_time</td><td class="v">3600</td><td class="v">3600</td></tr>
<tr><td class="e">max_file_uploads</td><td class="v">20</td><td class="v">20</td></tr>
<tr><td class="e">max_input_nesting_level</td><td class="v">64</td><td class="v">64</td></tr>
<tr><td class="e">max_input_time</td><td class="v">3600</td><td class="v">3600</td></tr>
<tr><td class="e">max_input_vars</td><td class="v">1000</td><td class="v">1000</td></tr>
<tr><td class="e">max_multipart_body_parts</td><td class="v">-1</td><td class="v">-1</td></tr>
<tr><td class="e">memory_limit</td><td class="v">512M</td><td class="v">128M</td></tr>
<tr><td class="e">open_basedir</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">output_buffering</td><td class="v">0</td><td class="v">4096</td></tr>
<tr><td class="e">output_encoding</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">output_handler</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">post_max_size</td><td class="v">513M</td><td class="v">20G</td></tr>
<tr><td class="e">precision</td><td class="v">14</td><td class="v">14</td></tr>
<tr><td class="e">realpath_cache_size</td><td class="v">4096K</td><td class="v">4096K</td></tr>
<tr><td class="e">realpath_cache_ttl</td><td class="v">120</td><td class="v">120</td></tr>
<tr><td class="e">register_argc_argv</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">report_memleaks</td><td class="v">On</td><td class="v">On</td></tr>
<tr><td class="e">report_zend_debug</td><td class="v">On</td><td class="v">On</td></tr>
<tr><td class="e">request_order</td><td class="v">GP</td><td class="v">GP</td></tr>
<tr><td class="e">sendmail_from</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">sendmail_path</td><td class="v">/usr/sbin/sendmail&nbsp;-t&nbsp;-i&nbsp;</td><td class="v">/usr/sbin/sendmail&nbsp;-t&nbsp;-i&nbsp;</td></tr>
<tr><td class="e">serialize_precision</td><td class="v">-1</td><td class="v">-1</td></tr>
<tr><td class="e">short_open_tag</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">SMTP</td><td class="v">localhost</td><td class="v">localhost</td></tr>
<tr><td class="e">smtp_port</td><td class="v">25</td><td class="v">25</td></tr>
<tr><td class="e">sys_temp_dir</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">syslog.facility</td><td class="v">LOG_USER</td><td class="v">LOG_USER</td></tr>
<tr><td class="e">syslog.filter</td><td class="v">no-ctrl</td><td class="v">no-ctrl</td></tr>
<tr><td class="e">syslog.ident</td><td class="v">php</td><td class="v">php</td></tr>
<tr><td class="e">track_errors</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">unserialize_callback_func</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">upload_max_filesize</td><td class="v">513M</td><td class="v">20G</td></tr>
<tr><td class="e">upload_tmp_dir</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">user_dir</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">user_ini.cache_ttl</td><td class="v">300</td><td class="v">300</td></tr>
<tr><td class="e">user_ini.filename</td><td class="v">.user.ini</td><td class="v">.user.ini</td></tr>
<tr><td class="e">variables_order</td><td class="v">EGPCS</td><td class="v">EGPCS</td></tr>
<tr><td class="e">xmlrpc_error_number</td><td class="v">0</td><td class="v">0</td></tr>
<tr><td class="e">xmlrpc_errors</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">zend.assertions</td><td class="v">-1</td><td class="v">-1</td></tr>
<tr><td class="e">zend.detect_unicode</td><td class="v">On</td><td class="v">On</td></tr>
<tr><td class="e">zend.enable_gc</td><td class="v">On</td><td class="v">On</td></tr>
<tr><td class="e">zend.exception_ignore_args</td><td class="v">On</td><td class="v">On</td></tr>
<tr><td class="e">zend.multibyte</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">zend.script_encoding</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">zend.signal_check</td><td class="v">Off</td><td class="v">Off</td></tr>
</tbody></table>
<h2><a name="module_ctype">ctype</a></h2>
<table>
<tbody><tr><td class="e">ctype functions </td><td class="v">enabled </td></tr>
</tbody></table>
<h2><a name="module_curl">curl</a></h2>
<table>
<tbody><tr><td class="e">cURL support </td><td class="v">enabled </td></tr>
<tr><td class="e">cURL Information </td><td class="v">7.68.0 </td></tr>
<tr><td class="e">Age </td><td class="v">5 </td></tr>
<tr><td class="e">Features </td></tr>
<tr><td class="e">AsynchDNS </td><td class="v">Yes </td></tr>
<tr><td class="e">CharConv </td><td class="v">No </td></tr>
<tr><td class="e">Debug </td><td class="v">No </td></tr>
<tr><td class="e">GSS-Negotiate </td><td class="v">No </td></tr>
<tr><td class="e">IDN </td><td class="v">Yes </td></tr>
<tr><td class="e">IPv6 </td><td class="v">Yes </td></tr>
<tr><td class="e">krb4 </td><td class="v">No </td></tr>
<tr><td class="e">Largefile </td><td class="v">Yes </td></tr>
<tr><td class="e">libz </td><td class="v">Yes </td></tr>
<tr><td class="e">NTLM </td><td class="v">Yes </td></tr>
<tr><td class="e">NTLMWB </td><td class="v">Yes </td></tr>
<tr><td class="e">SPNEGO </td><td class="v">Yes </td></tr>
<tr><td class="e">SSL </td><td class="v">Yes </td></tr>
<tr><td class="e">SSPI </td><td class="v">No </td></tr>
<tr><td class="e">TLS-SRP </td><td class="v">Yes </td></tr>
<tr><td class="e">HTTP2 </td><td class="v">Yes </td></tr>
<tr><td class="e">GSSAPI </td><td class="v">Yes </td></tr>
<tr><td class="e">KERBEROS5 </td><td class="v">Yes </td></tr>
<tr><td class="e">UNIX_SOCKETS </td><td class="v">Yes </td></tr>
<tr><td class="e">PSL </td><td class="v">Yes </td></tr>
<tr><td class="e">HTTPS_PROXY </td><td class="v">Yes </td></tr>
<tr><td class="e">MULTI_SSL </td><td class="v">No </td></tr>
<tr><td class="e">BROTLI </td><td class="v">Yes </td></tr>
<tr><td class="e">Protocols </td><td class="v">dict, file, ftp, ftps, gopher, http, https, imap, imaps, ldap, ldaps, pop3, pop3s, rtmp, rtsp, scp, sftp, smb, smbs, smtp, smtps, telnet, tftp </td></tr>
<tr><td class="e">Host </td><td class="v">x86_64-pc-linux-gnu </td></tr>
<tr><td class="e">SSL Version </td><td class="v">OpenSSL/1.1.1f </td></tr>
<tr><td class="e">ZLib Version </td><td class="v">1.2.11 </td></tr>
<tr><td class="e">libSSH Version </td><td class="v">libssh/0.9.3/openssl/zlib </td></tr>
</tbody></table>
<table>
<tbody><tr class="h"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>
<tr><td class="e">curl.cainfo</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
</tbody></table>
<h2><a name="module_date">date</a></h2>
<table>
<tbody><tr><td class="e">date/time support </td><td class="v">enabled </td></tr>
<tr><td class="e">timelib version </td><td class="v">2018.03 </td></tr>
<tr><td class="e">"Olson" Timezone Database Version </td><td class="v">0.system </td></tr>
<tr><td class="e">Timezone Database </td><td class="v">internal </td></tr>
<tr><td class="e">Default timezone </td><td class="v">UTC </td></tr>
</tbody></table>
<table>
<tbody><tr class="h"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>
<tr><td class="e">date.default_latitude</td><td class="v">31.7667</td><td class="v">31.7667</td></tr>
<tr><td class="e">date.default_longitude</td><td class="v">35.2333</td><td class="v">35.2333</td></tr>
<tr><td class="e">date.sunrise_zenith</td><td class="v">90.583333</td><td class="v">90.583333</td></tr>
<tr><td class="e">date.sunset_zenith</td><td class="v">90.583333</td><td class="v">90.583333</td></tr>
<tr><td class="e">date.timezone</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
</tbody></table>
<h2><a name="module_dom">dom</a></h2>
<table>
<tbody><tr><td class="e">DOM/XML </td><td class="v">enabled </td></tr>
<tr><td class="e">DOM/XML API Version </td><td class="v">20031129 </td></tr>
<tr><td class="e">libxml Version </td><td class="v">2.9.10 </td></tr>
<tr><td class="e">HTML Support </td><td class="v">enabled </td></tr>
<tr><td class="e">XPath Support </td><td class="v">enabled </td></tr>
<tr><td class="e">XPointer Support </td><td class="v">enabled </td></tr>
<tr><td class="e">Schema Support </td><td class="v">enabled </td></tr>
<tr><td class="e">RelaxNG Support </td><td class="v">enabled </td></tr>
</tbody></table>
<h2><a name="module_exif">exif</a></h2>
<table>
<tbody><tr><td class="e">EXIF Support </td><td class="v">enabled </td></tr>
<tr><td class="e">Supported EXIF Version </td><td class="v">0220 </td></tr>
<tr><td class="e">Supported filetypes </td><td class="v">JPEG, TIFF </td></tr>
<tr><td class="e">Multibyte decoding support using mbstring </td><td class="v">enabled </td></tr>
<tr><td class="e">Extended EXIF tag formats </td><td class="v">Canon, Casio, Fujifilm, Nikon, Olympus, Samsung, Panasonic, DJI, Sony, Pentax, Minolta, Sigma, Foveon, Kyocera, Ricoh, AGFA, Epson </td></tr>
</tbody></table>
<table>
<tbody><tr class="h"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>
<tr><td class="e">exif.decode_jis_intel</td><td class="v">JIS</td><td class="v">JIS</td></tr>
<tr><td class="e">exif.decode_jis_motorola</td><td class="v">JIS</td><td class="v">JIS</td></tr>
<tr><td class="e">exif.decode_unicode_intel</td><td class="v">UCS-2LE</td><td class="v">UCS-2LE</td></tr>
<tr><td class="e">exif.decode_unicode_motorola</td><td class="v">UCS-2BE</td><td class="v">UCS-2BE</td></tr>
<tr><td class="e">exif.encode_jis</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">exif.encode_unicode</td><td class="v">ISO-8859-15</td><td class="v">ISO-8859-15</td></tr>
</tbody></table>
<h2><a name="module_ffi">FFI</a></h2>
<table>
<tbody><tr class="h"><th>FFI support</th><th>enabled</th></tr>
</tbody></table>
<table>
<tbody><tr class="h"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>
<tr><td class="e">ffi.enable</td><td class="v">preload</td><td class="v">preload</td></tr>
<tr><td class="e">ffi.preload</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
</tbody></table>
<h2><a name="module_fileinfo">fileinfo</a></h2>
<table>
<tbody><tr><td class="e">fileinfo support </td><td class="v">enabled </td></tr>
<tr><td class="e">libmagic </td><td class="v">537 </td></tr>
</tbody></table>
<h2><a name="module_filter">filter</a></h2>
<table>
<tbody><tr><td class="e">Input Validation and Filtering </td><td class="v">enabled </td></tr>
</tbody></table>
<table>
<tbody><tr class="h"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>
<tr><td class="e">filter.default</td><td class="v">unsafe_raw</td><td class="v">unsafe_raw</td></tr>
<tr><td class="e">filter.default_flags</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
</tbody></table>
<h2><a name="module_ftp">ftp</a></h2>
<table>
<tbody><tr><td class="e">FTP support </td><td class="v">enabled </td></tr>
<tr><td class="e">FTPS support </td><td class="v">enabled </td></tr>
</tbody></table>
<h2><a name="module_gd">gd</a></h2>
<table>
<tbody><tr><td class="e">GD Support </td><td class="v">enabled </td></tr>
<tr><td class="e">GD headers Version </td><td class="v">2.2.5 </td></tr>
<tr><td class="e">GD library Version </td><td class="v">2.2.5 </td></tr>
<tr><td class="e">FreeType Support </td><td class="v">enabled </td></tr>
<tr><td class="e">FreeType Linkage </td><td class="v">with freetype </td></tr>
<tr><td class="e">GIF Read Support </td><td class="v">enabled </td></tr>
<tr><td class="e">GIF Create Support </td><td class="v">enabled </td></tr>
<tr><td class="e">JPEG Support </td><td class="v">enabled </td></tr>
<tr><td class="e">PNG Support </td><td class="v">enabled </td></tr>
<tr><td class="e">WBMP Support </td><td class="v">enabled </td></tr>
<tr><td class="e">XPM Support </td><td class="v">enabled </td></tr>
<tr><td class="e">XBM Support </td><td class="v">enabled </td></tr>
<tr><td class="e">WebP Support </td><td class="v">enabled </td></tr>
<tr><td class="e">BMP Support </td><td class="v">enabled </td></tr>
<tr><td class="e">TGA Read Support </td><td class="v">enabled </td></tr>
</tbody></table>
<table>
<tbody><tr class="h"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>
<tr><td class="e">gd.jpeg_ignore_warning</td><td class="v">1</td><td class="v">1</td></tr>
</tbody></table>
<h2><a name="module_gettext">gettext</a></h2>
<table>
<tbody><tr><td class="e">GetText Support </td><td class="v">enabled </td></tr>
</tbody></table>
<h2><a name="module_gmp">gmp</a></h2>
<table>
<tbody><tr><td class="e">gmp support </td><td class="v">enabled </td></tr>
<tr><td class="e">GMP version </td><td class="v">6.2.0 </td></tr>
</tbody></table>
<h2><a name="module_hash">hash</a></h2>
<table>
<tbody><tr><td class="e">hash support </td><td class="v">enabled </td></tr>
<tr><td class="e">Hashing Engines </td><td class="v">md2 md4 md5 sha1 sha224 sha256 sha384 sha512/224 sha512/256 sha512 sha3-224 sha3-256 sha3-384 sha3-512 ripemd128 ripemd160 ripemd256 ripemd320 whirlpool tiger128,3 tiger160,3 tiger192,3 tiger128,4 tiger160,4 tiger192,4 snefru snefru256 gost gost-crypto adler32 crc32 crc32b crc32c fnv132 fnv1a32 fnv164 fnv1a64 joaat haval128,3 haval160,3 haval192,3 haval224,3 haval256,3 haval128,4 haval160,4 haval192,4 haval224,4 haval256,4 haval128,5 haval160,5 haval192,5 haval224,5 haval256,5  </td></tr>
</tbody></table>
<table>
<tbody><tr><td class="e">MHASH support </td><td class="v">Enabled </td></tr>
<tr><td class="e">MHASH API Version </td><td class="v">Emulated Support </td></tr>
</tbody></table>
<h2><a name="module_iconv">iconv</a></h2>
<table>
<tbody><tr><td class="e">iconv support </td><td class="v">enabled </td></tr>
<tr><td class="e">iconv implementation </td><td class="v">glibc </td></tr>
<tr><td class="e">iconv library version </td><td class="v">2.31 </td></tr>
</tbody></table>
<table>
<tbody><tr class="h"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>
<tr><td class="e">iconv.input_encoding</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">iconv.internal_encoding</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">iconv.output_encoding</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
</tbody></table>
<h2><a name="module_igbinary">igbinary</a></h2>
<table>
<tbody><tr><td class="e">igbinary support </td><td class="v">enabled </td></tr>
<tr><td class="e">igbinary version </td><td class="v">3.1.2 </td></tr>
<tr><td class="e">igbinary APCu serializer ABI </td><td class="v">0 </td></tr>
<tr><td class="e">igbinary session support </td><td class="v">yes </td></tr>
</tbody></table>
<table>
<tbody><tr class="h"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>
<tr><td class="e">igbinary.compact_strings</td><td class="v">On</td><td class="v">On</td></tr>
</tbody></table>
<h2><a name="module_imagick">imagick</a></h2>
<table>
<tbody><tr class="h"><th>imagick module</th><th>enabled</th></tr>
<tr><td class="e">imagick module version </td><td class="v">3.4.4 </td></tr>
<tr><td class="e">imagick classes </td><td class="v">Imagick, ImagickDraw, ImagickPixel, ImagickPixelIterator, ImagickKernel </td></tr>
<tr><td class="e">Imagick compiled with ImageMagick version </td><td class="v">ImageMagick 6.9.10-23 Q16 x86_64 20190101 https://imagemagick.org </td></tr>
<tr><td class="e">Imagick using ImageMagick library version </td><td class="v">ImageMagick 6.9.10-23 Q16 x86_64 20190101 https://imagemagick.org </td></tr>
<tr><td class="e">ImageMagick copyright </td><td class="v">© 1999-2019 ImageMagick Studio LLC </td></tr>
<tr><td class="e">ImageMagick release date </td><td class="v">20190101 </td></tr>
<tr><td class="e">ImageMagick number of supported formats:  </td><td class="v">225 </td></tr>
<tr><td class="e">ImageMagick supported formats </td><td class="v">3FR, 3G2, 3GP, AAI, AI, ART, ARW, AVI, AVS, BGR, BGRA, BGRO, BIE, BMP, BMP2, BMP3, BRF, CAL, CALS, CANVAS, CAPTION, CIN, CIP, CLIP, CMYK, CMYKA, CR2, CRW, CUR, CUT, DATA, DCM, DCR, DCX, DDS, DFONT, DNG, DPX, DXT1, DXT5, EPDF, EPI, EPS, EPS2, EPS3, EPSF, EPSI, EPT, EPT2, EPT3, ERF, FAX, FILE, FITS, FRACTAL, FTP, FTS, G3, G4, GIF, GIF87, GRADIENT, GRAY, GRAYA, GROUP4, H, HALD, HDR, HISTOGRAM, HRZ, HTM, HTML, HTTP, HTTPS, ICB, ICO, ICON, IIQ, INFO, INLINE, IPL, ISOBRL, ISOBRL6, JBG, JBIG, JNG, JNX, JPE, JPEG, JPG, JPS, JSON, K25, KDC, LABEL, M2V, M4V, MAC, MAGICK, MAP, MASK, MAT, MATTE, MEF, MIFF, MKV, MNG, MONO, MOV, MP4, MPC, MPEG, MPG, MRW, MSL, MTV, MVG, NEF, NRW, NULL, ORF, OTB, OTF, PAL, PALM, PAM, PATTERN, PBM, PCD, PCDS, PCL, PCT, PCX, PDB, PDF, PDFA, PEF, PES, PFA, PFB, PFM, PGM, PGX, PICON, PICT, PIX, PJPEG, PLASMA, PNG, PNG00, PNG24, PNG32, PNG48, PNG64, PNG8, PNM, PPM, PREVIEW, PS, PS2, PS3, PSB, PSD, PTIF, PWP, RADIAL-GRADIENT, RAF, RAS, RAW, RGB, RGBA, RGBO, RGF, RLA, RLE, RMF, RW2, SCR, SCT, SFW, SGI, SHTML, SIX, SIXEL, SPARSE-COLOR, SR2, SRF, STEGANO, SUN, TEXT, TGA, THUMBNAIL, TIFF, TIFF64, TILE, TIM, TTC, TTF, TXT, UBRL, UBRL6, UIL, UYVY, VDA, VICAR, VID, VIFF, VIPS, VST, WBMP, WEBP, WMV, WPG, X, X3F, XBM, XC, XCF, XPM, XPS, XV, XWD, YCbCr, YCbCrA, YUV </td></tr>
</tbody></table>
<table>
<tbody><tr class="h"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>
<tr><td class="e">imagick.locale_fix</td><td class="v">0</td><td class="v">0</td></tr>
<tr><td class="e">imagick.progress_monitor</td><td class="v">0</td><td class="v">0</td></tr>
<tr><td class="e">imagick.skip_version_check</td><td class="v">1</td><td class="v">1</td></tr>
</tbody></table>
<h2><a name="module_intl">intl</a></h2>
<table>
<tbody><tr class="h"><th>Internationalization support</th><th>enabled</th></tr>
<tr><td class="e">ICU version </td><td class="v">66.1 </td></tr>
<tr><td class="e">ICU Data version </td><td class="v">66.1 </td></tr>
<tr><td class="e">ICU TZData version </td><td class="v">2022g </td></tr>
<tr><td class="e">ICU Unicode version </td><td class="v">13.0 </td></tr>
</tbody></table>
<table>
<tbody><tr class="h"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>
<tr><td class="e">intl.default_locale</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">intl.error_level</td><td class="v">0</td><td class="v">0</td></tr>
<tr><td class="e">intl.use_exceptions</td><td class="v">0</td><td class="v">0</td></tr>
</tbody></table>
<h2><a name="module_json">json</a></h2>
<table>
<tbody><tr><td class="e">json support </td><td class="v">enabled </td></tr>
</tbody></table>
<h2><a name="module_ldap">ldap</a></h2>
<table>
<tbody><tr><td class="e">LDAP Support </td><td class="v">enabled </td></tr>
<tr><td class="e">Total Links </td><td class="v">0/unlimited </td></tr>
<tr><td class="e">API Version </td><td class="v">3001 </td></tr>
<tr><td class="e">Vendor Name </td><td class="v">OpenLDAP </td></tr>
<tr><td class="e">Vendor Version </td><td class="v">20449 </td></tr>
<tr><td class="e">SASL Support </td><td class="v">Enabled </td></tr>
</tbody></table>
<table>
<tbody><tr class="h"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>
<tr><td class="e">ldap.max_links</td><td class="v">Unlimited</td><td class="v">Unlimited</td></tr>
</tbody></table>
<h2><a name="module_libsmbclient">libsmbclient</a></h2>
<table>
<tbody><tr><td class="e">Version </td><td class="v">1.0.6 </td></tr>
</tbody></table>
<h2><a name="module_libxml">libxml</a></h2>
<table>
<tbody><tr><td class="e">libXML support </td><td class="v">active </td></tr>
<tr><td class="e">libXML Compiled Version </td><td class="v">2.9.10 </td></tr>
<tr><td class="e">libXML Loaded Version </td><td class="v">20910 </td></tr>
<tr><td class="e">libXML streams </td><td class="v">enabled </td></tr>
</tbody></table>
<h2><a name="module_mbstring">mbstring</a></h2>
<table>
<tbody><tr><td class="e">Multibyte Support </td><td class="v">enabled </td></tr>
<tr><td class="e">Multibyte string engine </td><td class="v">libmbfl </td></tr>
<tr><td class="e">HTTP input encoding translation </td><td class="v">disabled </td></tr>
<tr><td class="e">libmbfl version </td><td class="v">1.3.2 </td></tr>
</tbody></table>
<table>
<tbody><tr class="h"><th>mbstring extension makes use of "streamable kanji code filter and converter", which is distributed under the GNU Lesser General Public License version 2.1.</th></tr>
</tbody></table>
<table>
<tbody><tr><td class="e">Multibyte (japanese) regex support </td><td class="v">enabled </td></tr>
<tr><td class="e">Multibyte regex (oniguruma) version </td><td class="v">6.9.4 </td></tr>
</tbody></table>
<table>
<tbody><tr class="h"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>
<tr><td class="e">mbstring.detect_order</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">mbstring.encoding_translation</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">mbstring.func_overload</td><td class="v">0</td><td class="v">0</td></tr>
<tr><td class="e">mbstring.http_input</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">mbstring.http_output</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">mbstring.http_output_conv_mimetypes</td><td class="v">^(text/|application/xhtml\+xml)</td><td class="v">^(text/|application/xhtml\+xml)</td></tr>
<tr><td class="e">mbstring.internal_encoding</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">mbstring.language</td><td class="v">neutral</td><td class="v">neutral</td></tr>
<tr><td class="e">mbstring.regex_retry_limit</td><td class="v">1000000</td><td class="v">1000000</td></tr>
<tr><td class="e">mbstring.regex_stack_limit</td><td class="v">100000</td><td class="v">100000</td></tr>
<tr><td class="e">mbstring.strict_detection</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">mbstring.substitute_character</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
</tbody></table>
<h2><a name="module_mysqli">mysqli</a></h2>
<table>
<tbody><tr class="h"><th>MysqlI Support</th><th>enabled</th></tr>
<tr><td class="e">Client API library version </td><td class="v">mysqlnd 7.4.3-4ubuntu2.18 </td></tr>
<tr><td class="e">Active Persistent Links </td><td class="v">0 </td></tr>
<tr><td class="e">Inactive Persistent Links </td><td class="v">0 </td></tr>
<tr><td class="e">Active Links </td><td class="v">0 </td></tr>
</tbody></table>
<table>
<tbody><tr class="h"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>
<tr><td class="e">mysqli.allow_local_infile</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">mysqli.allow_persistent</td><td class="v">On</td><td class="v">On</td></tr>
<tr><td class="e">mysqli.default_host</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">mysqli.default_port</td><td class="v">3306</td><td class="v">3306</td></tr>
<tr><td class="e">mysqli.default_pw</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">mysqli.default_socket</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">mysqli.default_user</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">mysqli.max_links</td><td class="v">Unlimited</td><td class="v">Unlimited</td></tr>
<tr><td class="e">mysqli.max_persistent</td><td class="v">Unlimited</td><td class="v">Unlimited</td></tr>
<tr><td class="e">mysqli.reconnect</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">mysqli.rollback_on_cached_plink</td><td class="v">Off</td><td class="v">Off</td></tr>
</tbody></table>
<h2><a name="module_mysqlnd">mysqlnd</a></h2>
<table>
<tbody><tr class="h"><th>mysqlnd</th><th>enabled</th></tr>
<tr><td class="e">Version </td><td class="v">mysqlnd 7.4.3-4ubuntu2.18 </td></tr>
<tr><td class="e">Compression </td><td class="v">supported </td></tr>
<tr><td class="e">core SSL </td><td class="v">supported </td></tr>
<tr><td class="e">extended SSL </td><td class="v">supported </td></tr>
<tr><td class="e">Command buffer size </td><td class="v">4096 </td></tr>
<tr><td class="e">Read buffer size </td><td class="v">32768 </td></tr>
<tr><td class="e">Read timeout </td><td class="v">86400 </td></tr>
<tr><td class="e">Collecting statistics </td><td class="v">Yes </td></tr>
<tr><td class="e">Collecting memory statistics </td><td class="v">No </td></tr>
<tr><td class="e">Tracing </td><td class="v">n/a </td></tr>
<tr><td class="e">Loaded plugins </td><td class="v">mysqlnd,debug_trace,auth_plugin_mysql_native_password,auth_plugin_mysql_clear_password,auth_plugin_caching_sha2_password,auth_plugin_sha256_password </td></tr>
<tr><td class="e">API Extensions </td><td class="v">mysqli,pdo_mysql </td></tr>
</tbody></table>
<h2><a name="module_openssl">openssl</a></h2>
<table>
<tbody><tr><td class="e">OpenSSL support </td><td class="v">enabled </td></tr>
<tr><td class="e">OpenSSL Library Version </td><td class="v">OpenSSL 1.1.1f  31 Mar 2020 </td></tr>
<tr><td class="e">OpenSSL Header Version </td><td class="v">OpenSSL 1.1.1f  31 Mar 2020 </td></tr>
<tr><td class="e">Openssl default config </td><td class="v">/usr/lib/ssl/openssl.cnf </td></tr>
</tbody></table>
<table>
<tbody><tr class="h"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>
<tr><td class="e">openssl.cafile</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">openssl.capath</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
</tbody></table>
<h2><a name="module_pcre">pcre</a></h2>
<table>
<tbody><tr><td class="e">PCRE (Perl Compatible Regular Expressions) Support </td><td class="v">enabled </td></tr>
<tr><td class="e">PCRE Library Version </td><td class="v">10.34 2019-11-21 </td></tr>
<tr><td class="e">PCRE Unicode Version </td><td class="v">12.1.0 </td></tr>
<tr><td class="e">PCRE JIT Support </td><td class="v">enabled </td></tr>
<tr><td class="e">PCRE JIT Target </td><td class="v">x86 64bit (little endian + unaligned) </td></tr>
</tbody></table>
<table>
<tbody><tr class="h"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>
<tr><td class="e">pcre.backtrack_limit</td><td class="v">1000000</td><td class="v">1000000</td></tr>
<tr><td class="e">pcre.jit</td><td class="v">1</td><td class="v">1</td></tr>
<tr><td class="e">pcre.recursion_limit</td><td class="v">100000</td><td class="v">100000</td></tr>
</tbody></table>
<h2><a name="module_pdo">PDO</a></h2>
<table>
<tbody><tr class="h"><th>PDO support</th><th>enabled</th></tr>
<tr><td class="e">PDO drivers </td><td class="v">mysql, pgsql, sqlite </td></tr>
</tbody></table>
<h2><a name="module_pdo_mysql">pdo_mysql</a></h2>
<table>
<tbody><tr class="h"><th>PDO Driver for MySQL</th><th>enabled</th></tr>
<tr><td class="e">Client API version </td><td class="v">mysqlnd 7.4.3-4ubuntu2.18 </td></tr>
</tbody></table>
<table>
<tbody><tr class="h"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>
<tr><td class="e">pdo_mysql.default_socket</td><td class="v">/var/run/mysqld/mysqld.sock</td><td class="v">/var/run/mysqld/mysqld.sock</td></tr>
</tbody></table>
<h2><a name="module_pdo_pgsql">pdo_pgsql</a></h2>
<table>
<tbody><tr><td class="e">PDO Driver for PostgreSQL </td><td class="v">enabled </td></tr>
<tr><td class="e">PostgreSQL(libpq) Version </td><td class="v">12.12 (Ubuntu 12.12-0ubuntu0.20.04.1) </td></tr>
</tbody></table>
<h2><a name="module_pdo_sqlite">pdo_sqlite</a></h2>
<table>
<tbody><tr class="h"><th>PDO Driver for SQLite 3.x</th><th>enabled</th></tr>
<tr><td class="e">SQLite Library </td><td class="v">3.31.1 </td></tr>
</tbody></table>
<h2><a name="module_pgsql">pgsql</a></h2>
<table>
<tbody><tr class="h"><th>PostgreSQL Support</th><th>enabled</th></tr>
<tr><td class="e">PostgreSQL(libpq) Version </td><td class="v">12.12 (Ubuntu 12.12-0ubuntu0.20.04.1) </td></tr>
<tr><td class="e">PostgreSQL(libpq)  </td><td class="v">PostgreSQL 12.12 (Ubuntu 12.12-0ubuntu0.20.04.1) on x86_64-pc-linux-gnu, compiled by gcc (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0, 64-bit </td></tr>
<tr><td class="e">Multibyte character support </td><td class="v">enabled </td></tr>
<tr><td class="e">SSL support </td><td class="v">enabled </td></tr>
<tr><td class="e">Active Persistent Links </td><td class="v">0 </td></tr>
<tr><td class="e">Active Links </td><td class="v">0 </td></tr>
</tbody></table>
<table>
<tbody><tr class="h"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>
<tr><td class="e">pgsql.allow_persistent</td><td class="v">On</td><td class="v">On</td></tr>
<tr><td class="e">pgsql.auto_reset_persistent</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">pgsql.ignore_notice</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">pgsql.log_notice</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">pgsql.max_links</td><td class="v">Unlimited</td><td class="v">Unlimited</td></tr>
<tr><td class="e">pgsql.max_persistent</td><td class="v">Unlimited</td><td class="v">Unlimited</td></tr>
</tbody></table>
<h2><a name="module_phar">Phar</a></h2>
<table>
<tbody><tr class="h"><th>Phar: PHP Archive support</th><th>enabled</th></tr>
<tr><td class="e">Phar API version </td><td class="v">1.1.1 </td></tr>
<tr><td class="e">Phar-based phar archives </td><td class="v">enabled </td></tr>
<tr><td class="e">Tar-based phar archives </td><td class="v">enabled </td></tr>
<tr><td class="e">ZIP-based phar archives </td><td class="v">enabled </td></tr>
<tr><td class="e">gzip compression </td><td class="v">enabled </td></tr>
<tr><td class="e">bzip2 compression </td><td class="v">disabled (install ext/bz2) </td></tr>
<tr><td class="e">Native OpenSSL support </td><td class="v">enabled </td></tr>
</tbody></table>
<table>
<tbody><tr class="v"><td>
Phar based on pear/PHP_Archive, original concept by Davey Shafik.<br>Phar fully realized by Gregory Beaver and Marcus Boerger.<br>Portions of tar implementation Copyright (c) 2003-2009 Tim Kientzle.</td></tr>
</tbody></table>
<table>
<tbody><tr class="h"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>
<tr><td class="e">phar.cache_list</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">phar.readonly</td><td class="v">On</td><td class="v">On</td></tr>
<tr><td class="e">phar.require_hash</td><td class="v">On</td><td class="v">On</td></tr>
</tbody></table>
<h2><a name="module_posix">posix</a></h2>
<table>
<tbody><tr><td class="e">POSIX support </td><td class="v">enabled </td></tr>
</tbody></table>
<h2><a name="module_readline">readline</a></h2>
<table>
<tbody><tr class="h"><th>Readline Support</th><th>enabled</th></tr>
<tr><td class="e">Readline library </td><td class="v">EditLine wrapper </td></tr>
</tbody></table>
<table>
<tbody><tr class="h"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>
<tr><td class="e">cli.pager</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">cli.prompt</td><td class="v">\b&nbsp;\&gt;&nbsp;</td><td class="v">\b&nbsp;\&gt;&nbsp;</td></tr>
</tbody></table>
<h2><a name="module_redis">redis</a></h2>
<table>
<tbody><tr class="h"><th>Redis Support</th><th>enabled</th></tr>
<tr><td class="e">Redis Version </td><td class="v">5.1.1 </td></tr>
<tr><td class="e">Available serializers </td><td class="v">php, json, igbinary </td></tr>
</tbody></table>
<table>
<tbody><tr class="h"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>
<tr><td class="e">redis.arrays.algorithm</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">redis.arrays.auth</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">redis.arrays.autorehash</td><td class="v">0</td><td class="v">0</td></tr>
<tr><td class="e">redis.arrays.connecttimeout</td><td class="v">0</td><td class="v">0</td></tr>
<tr><td class="e">redis.arrays.consistent</td><td class="v">0</td><td class="v">0</td></tr>
<tr><td class="e">redis.arrays.distributor</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">redis.arrays.functions</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">redis.arrays.hosts</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">redis.arrays.index</td><td class="v">0</td><td class="v">0</td></tr>
<tr><td class="e">redis.arrays.lazyconnect</td><td class="v">0</td><td class="v">0</td></tr>
<tr><td class="e">redis.arrays.names</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">redis.arrays.pconnect</td><td class="v">0</td><td class="v">0</td></tr>
<tr><td class="e">redis.arrays.previous</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">redis.arrays.readtimeout</td><td class="v">0</td><td class="v">0</td></tr>
<tr><td class="e">redis.arrays.retryinterval</td><td class="v">0</td><td class="v">0</td></tr>
<tr><td class="e">redis.clusters.auth</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">redis.clusters.cache_slots</td><td class="v">0</td><td class="v">0</td></tr>
<tr><td class="e">redis.clusters.persistent</td><td class="v">0</td><td class="v">0</td></tr>
<tr><td class="e">redis.clusters.read_timeout</td><td class="v">0</td><td class="v">0</td></tr>
<tr><td class="e">redis.clusters.seeds</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">redis.clusters.timeout</td><td class="v">0</td><td class="v">0</td></tr>
<tr><td class="e">redis.pconnect.connection_limit</td><td class="v">0</td><td class="v">0</td></tr>
<tr><td class="e">redis.pconnect.pooling_enabled</td><td class="v">1</td><td class="v">1</td></tr>
<tr><td class="e">redis.session.lock_expire</td><td class="v">0</td><td class="v">0</td></tr>
<tr><td class="e">redis.session.lock_retries</td><td class="v">10</td><td class="v">10</td></tr>
<tr><td class="e">redis.session.lock_wait_time</td><td class="v">2000</td><td class="v">2000</td></tr>
<tr><td class="e">redis.session.locking_enabled</td><td class="v">0</td><td class="v">0</td></tr>
</tbody></table>
<h2><a name="module_reflection">Reflection</a></h2>
<table>
<tbody><tr><td class="e">Reflection </td><td class="v">enabled </td></tr>
</tbody></table>
<h2><a name="module_session">session</a></h2>
<table>
<tbody><tr><td class="e">Session Support </td><td class="v">enabled </td></tr>
<tr><td class="e">Registered save handlers </td><td class="v">files user redis rediscluster  </td></tr>
<tr><td class="e">Registered serializer handlers </td><td class="v">php_serialize php php_binary igbinary  </td></tr>
</tbody></table>
<table>
<tbody><tr class="h"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>
<tr><td class="e">session.auto_start</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">session.cache_expire</td><td class="v">180</td><td class="v">180</td></tr>
<tr><td class="e">session.cache_limiter</td><td class="v">nocache</td><td class="v">nocache</td></tr>
<tr><td class="e">session.cookie_domain</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">session.cookie_httponly</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">session.cookie_lifetime</td><td class="v">0</td><td class="v">0</td></tr>
<tr><td class="e">session.cookie_path</td><td class="v">/</td><td class="v">/</td></tr>
<tr><td class="e">session.cookie_samesite</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">session.cookie_secure</td><td class="v">0</td><td class="v">0</td></tr>
<tr><td class="e">session.gc_divisor</td><td class="v">1000</td><td class="v">1000</td></tr>
<tr><td class="e">session.gc_maxlifetime</td><td class="v">1440</td><td class="v">1440</td></tr>
<tr><td class="e">session.gc_probability</td><td class="v">0</td><td class="v">0</td></tr>
<tr><td class="e">session.lazy_write</td><td class="v">On</td><td class="v">On</td></tr>
<tr><td class="e">session.name</td><td class="v">PHPSESSID</td><td class="v">PHPSESSID</td></tr>
<tr><td class="e">session.referer_check</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">session.save_handler</td><td class="v">files</td><td class="v">files</td></tr>
<tr><td class="e">session.save_path</td><td class="v">/mnt/data/sessions</td><td class="v">/mnt/data/sessions</td></tr>
<tr><td class="e">session.serialize_handler</td><td class="v">php</td><td class="v">php</td></tr>
<tr><td class="e">session.sid_bits_per_character</td><td class="v">5</td><td class="v">5</td></tr>
<tr><td class="e">session.sid_length</td><td class="v">26</td><td class="v">26</td></tr>
<tr><td class="e">session.upload_progress.cleanup</td><td class="v">On</td><td class="v">On</td></tr>
<tr><td class="e">session.upload_progress.enabled</td><td class="v">On</td><td class="v">On</td></tr>
<tr><td class="e">session.upload_progress.freq</td><td class="v">1%</td><td class="v">1%</td></tr>
<tr><td class="e">session.upload_progress.min_freq</td><td class="v">1</td><td class="v">1</td></tr>
<tr><td class="e">session.upload_progress.name</td><td class="v">PHP_SESSION_UPLOAD_PROGRESS</td><td class="v">PHP_SESSION_UPLOAD_PROGRESS</td></tr>
<tr><td class="e">session.upload_progress.prefix</td><td class="v">upload_progress_</td><td class="v">upload_progress_</td></tr>
<tr><td class="e">session.use_cookies</td><td class="v">1</td><td class="v">1</td></tr>
<tr><td class="e">session.use_only_cookies</td><td class="v">1</td><td class="v">1</td></tr>
<tr><td class="e">session.use_strict_mode</td><td class="v">0</td><td class="v">0</td></tr>
<tr><td class="e">session.use_trans_sid</td><td class="v">0</td><td class="v">0</td></tr>
</tbody></table>
<h2><a name="module_shmop">shmop</a></h2>
<table>
<tbody><tr><td class="e">shmop support </td><td class="v">enabled </td></tr>
</tbody></table>
<h2><a name="module_simplexml">SimpleXML</a></h2>
<table>
<tbody><tr><td class="e">SimpleXML support </td><td class="v">enabled </td></tr>
<tr><td class="e">Schema support </td><td class="v">enabled </td></tr>
</tbody></table>
<h2><a name="module_smbclient">smbclient</a></h2>
<table>
<tbody><tr><td class="e">smbclient Support </td><td class="v">enabled </td></tr>
<tr><td class="e">smbclient extension Version </td><td class="v">1.0.6 </td></tr>
<tr><td class="e">libsmbclient library Version </td><td class="v">4.13.17-Ubuntu </td></tr>
</tbody></table>
<h2><a name="module_soap">soap</a></h2>
<table>
<tbody><tr><td class="e">Soap Client </td><td class="v">enabled </td></tr>
<tr><td class="e">Soap Server </td><td class="v">enabled </td></tr>
</tbody></table>
<table>
<tbody><tr class="h"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>
<tr><td class="e">soap.wsdl_cache</td><td class="v">1</td><td class="v">1</td></tr>
<tr><td class="e">soap.wsdl_cache_dir</td><td class="v">/tmp</td><td class="v">/tmp</td></tr>
<tr><td class="e">soap.wsdl_cache_enabled</td><td class="v">1</td><td class="v">1</td></tr>
<tr><td class="e">soap.wsdl_cache_limit</td><td class="v">5</td><td class="v">5</td></tr>
<tr><td class="e">soap.wsdl_cache_ttl</td><td class="v">86400</td><td class="v">86400</td></tr>
</tbody></table>
<h2><a name="module_sockets">sockets</a></h2>
<table>
<tbody><tr><td class="e">Sockets Support </td><td class="v">enabled </td></tr>
</tbody></table>
<h2><a name="module_sodium">sodium</a></h2>
<table>
<tbody><tr class="h"><th>sodium support</th><th>enabled</th></tr>
<tr><td class="e">libsodium headers version </td><td class="v">1.0.18 </td></tr>
<tr><td class="e">libsodium library version </td><td class="v">1.0.18 </td></tr>
</tbody></table>
<h2><a name="module_spl">SPL</a></h2>
<table>
<tbody><tr class="h"><th>SPL support</th><th>enabled</th></tr>
<tr><td class="e">Interfaces </td><td class="v">OuterIterator, RecursiveIterator, SeekableIterator, SplObserver, SplSubject </td></tr>
<tr><td class="e">Classes </td><td class="v">AppendIterator, ArrayIterator, ArrayObject, BadFunctionCallException, BadMethodCallException, CachingIterator, CallbackFilterIterator, DirectoryIterator, DomainException, EmptyIterator, FilesystemIterator, FilterIterator, GlobIterator, InfiniteIterator, InvalidArgumentException, IteratorIterator, LengthException, LimitIterator, LogicException, MultipleIterator, NoRewindIterator, OutOfBoundsException, OutOfRangeException, OverflowException, ParentIterator, RangeException, RecursiveArrayIterator, RecursiveCachingIterator, RecursiveCallbackFilterIterator, RecursiveDirectoryIterator, RecursiveFilterIterator, RecursiveIteratorIterator, RecursiveRegexIterator, RecursiveTreeIterator, RegexIterator, RuntimeException, SplDoublyLinkedList, SplFileInfo, SplFileObject, SplFixedArray, SplHeap, SplMinHeap, SplMaxHeap, SplObjectStorage, SplPriorityQueue, SplQueue, SplStack, SplTempFileObject, UnderflowException, UnexpectedValueException </td></tr>
</tbody></table>
<h2><a name="module_sqlite3">sqlite3</a></h2>
<table>
<tbody><tr class="h"><th>SQLite3 support</th><th>enabled</th></tr>
<tr><td class="e">SQLite Library </td><td class="v">3.31.1 </td></tr>
</tbody></table>
<table>
<tbody><tr class="h"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>
<tr><td class="e">sqlite3.defensive</td><td class="v">1</td><td class="v">1</td></tr>
<tr><td class="e">sqlite3.extension_dir</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
</tbody></table>
<h2><a name="module_standard">standard</a></h2>
<table>
<tbody><tr><td class="e">Dynamic Library Support </td><td class="v">enabled </td></tr>
<tr><td class="e">Path to sendmail </td><td class="v">/usr/sbin/sendmail -t -i  </td></tr>
</tbody></table>
<table>
<tbody><tr class="h"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>
<tr><td class="e">assert.active</td><td class="v">1</td><td class="v">1</td></tr>
<tr><td class="e">assert.bail</td><td class="v">0</td><td class="v">0</td></tr>
<tr><td class="e">assert.callback</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">assert.exception</td><td class="v">0</td><td class="v">0</td></tr>
<tr><td class="e">assert.quiet_eval</td><td class="v">0</td><td class="v">0</td></tr>
<tr><td class="e">assert.warning</td><td class="v">1</td><td class="v">1</td></tr>
<tr><td class="e">auto_detect_line_endings</td><td class="v">0</td><td class="v">0</td></tr>
<tr><td class="e">default_socket_timeout</td><td class="v">60</td><td class="v">60</td></tr>
<tr><td class="e">from</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">session.trans_sid_hosts</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">session.trans_sid_tags</td><td class="v">a=href,area=href,frame=src,form=</td><td class="v">a=href,area=href,frame=src,form=</td></tr>
<tr><td class="e">unserialize_max_depth</td><td class="v">4096</td><td class="v">4096</td></tr>
<tr><td class="e">url_rewriter.hosts</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">url_rewriter.tags</td><td class="v">form=</td><td class="v">form=</td></tr>
<tr><td class="e">user_agent</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
</tbody></table>
<h2><a name="module_sysvmsg">sysvmsg</a></h2>
<table>
<tbody><tr><td class="e">sysvmsg support </td><td class="v">enabled </td></tr>
</tbody></table>
<h2><a name="module_sysvsem">sysvsem</a></h2>
<table>
<tbody><tr><td class="e">sysvsem support </td><td class="v">enabled </td></tr>
</tbody></table>
<h2><a name="module_sysvshm">sysvshm</a></h2>
<table>
<tbody><tr><td class="e">sysvshm support </td><td class="v">enabled </td></tr>
</tbody></table>
<h2><a name="module_tokenizer">tokenizer</a></h2>
<table>
<tbody><tr><td class="e">Tokenizer Support </td><td class="v">enabled </td></tr>
</tbody></table>
<h2><a name="module_xml">xml</a></h2>
<table>
<tbody><tr><td class="e">XML Support </td><td class="v">active </td></tr>
<tr><td class="e">XML Namespace Support </td><td class="v">active </td></tr>
<tr><td class="e">libxml2 Version </td><td class="v">2.9.10 </td></tr>
</tbody></table>
<h2><a name="module_xmlreader">xmlreader</a></h2>
<table>
<tbody><tr><td class="e">XMLReader </td><td class="v">enabled </td></tr>
</tbody></table>
<h2><a name="module_xmlwriter">xmlwriter</a></h2>
<table>
<tbody><tr><td class="e">XMLWriter </td><td class="v">enabled </td></tr>
</tbody></table>
<h2><a name="module_xsl">xsl</a></h2>
<table>
<tbody><tr><td class="e">XSL </td><td class="v">enabled </td></tr>
<tr><td class="e">libxslt Version </td><td class="v">1.1.34 </td></tr>
<tr><td class="e">libxslt compiled against libxml Version </td><td class="v">2.9.10 </td></tr>
<tr><td class="e">EXSLT </td><td class="v">enabled </td></tr>
<tr><td class="e">libexslt Version </td><td class="v">1.1.34 </td></tr>
</tbody></table>
<h2><a name="module_zend+opcache">Zend OPcache</a></h2>
<table>
<tbody><tr><td class="e">Opcode Caching </td><td class="v">Up and Running </td></tr>
<tr><td class="e">Optimization </td><td class="v">Enabled </td></tr>
<tr><td class="e">SHM Cache </td><td class="v">Enabled </td></tr>
<tr><td class="e">File Cache </td><td class="v">Disabled </td></tr>
<tr><td class="e">Startup </td><td class="v">OK </td></tr>
<tr><td class="e">Shared memory model </td><td class="v">mmap </td></tr>
<tr><td class="e">Cache hits </td><td class="v">12336 </td></tr>
<tr><td class="e">Cache misses </td><td class="v">551 </td></tr>
<tr><td class="e">Used memory </td><td class="v">19971592 </td></tr>
<tr><td class="e">Free memory </td><td class="v">114246136 </td></tr>
<tr><td class="e">Wasted memory </td><td class="v">0 </td></tr>
<tr><td class="e">Interned Strings Used memory </td><td class="v">6289992 </td></tr>
<tr><td class="e">Interned Strings Free memory </td><td class="v">1016 </td></tr>
<tr><td class="e">Cached scripts </td><td class="v">551 </td></tr>
<tr><td class="e">Cached keys </td><td class="v">1046 </td></tr>
<tr><td class="e">Max keys </td><td class="v">16229 </td></tr>
<tr><td class="e">OOM restarts </td><td class="v">0 </td></tr>
<tr><td class="e">Hash keys restarts </td><td class="v">0 </td></tr>
<tr><td class="e">Manual restarts </td><td class="v">0 </td></tr>
</tbody></table>
<table>
<tbody><tr class="h"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>
<tr><td class="e">opcache.blacklist_filename</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">opcache.consistency_checks</td><td class="v">0</td><td class="v">0</td></tr>
<tr><td class="e">opcache.dups_fix</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">opcache.enable</td><td class="v">On</td><td class="v">On</td></tr>
<tr><td class="e">opcache.enable_cli</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">opcache.enable_file_override</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">opcache.error_log</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">opcache.file_cache</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">opcache.file_cache_consistency_checks</td><td class="v">1</td><td class="v">1</td></tr>
<tr><td class="e">opcache.file_cache_only</td><td class="v">0</td><td class="v">0</td></tr>
<tr><td class="e">opcache.file_update_protection</td><td class="v">2</td><td class="v">2</td></tr>
<tr><td class="e">opcache.force_restart_timeout</td><td class="v">180</td><td class="v">180</td></tr>
<tr><td class="e">opcache.huge_code_pages</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">opcache.interned_strings_buffer</td><td class="v">8</td><td class="v">8</td></tr>
<tr><td class="e">opcache.lockfile_path</td><td class="v">/tmp</td><td class="v">/tmp</td></tr>
<tr><td class="e">opcache.log_verbosity_level</td><td class="v">1</td><td class="v">1</td></tr>
<tr><td class="e">opcache.max_accelerated_files</td><td class="v">10000</td><td class="v">10000</td></tr>
<tr><td class="e">opcache.max_file_size</td><td class="v">0</td><td class="v">0</td></tr>
<tr><td class="e">opcache.max_wasted_percentage</td><td class="v">5</td><td class="v">5</td></tr>
<tr><td class="e">opcache.memory_consumption</td><td class="v">128</td><td class="v">128</td></tr>
<tr><td class="e">opcache.opt_debug_level</td><td class="v">0</td><td class="v">0</td></tr>
<tr><td class="e">opcache.optimization_level</td><td class="v">0x7FFEBFFF</td><td class="v">0x7FFEBFFF</td></tr>
<tr><td class="e">opcache.preferred_memory_model</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">opcache.preload</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">opcache.preload_user</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">opcache.protect_memory</td><td class="v">0</td><td class="v">0</td></tr>
<tr><td class="e">opcache.restrict_api</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">opcache.revalidate_freq</td><td class="v">2</td><td class="v">2</td></tr>
<tr><td class="e">opcache.revalidate_path</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">opcache.save_comments</td><td class="v">1</td><td class="v">1</td></tr>
<tr><td class="e">opcache.use_cwd</td><td class="v">On</td><td class="v">On</td></tr>
<tr><td class="e">opcache.validate_permission</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">opcache.validate_root</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">opcache.validate_timestamps</td><td class="v">On</td><td class="v">On</td></tr>
</tbody></table>
<h2><a name="module_zip">zip</a></h2>
<table>
<tbody><tr><td class="e">Zip </td><td class="v">enabled </td></tr>
<tr><td class="e">Zip version </td><td class="v">1.15.6 </td></tr>
<tr><td class="e">Libzip headers version </td><td class="v">1.5.1 </td></tr>
<tr><td class="e">Libzip library version </td><td class="v">1.5.1 </td></tr>
</tbody></table>
<h2><a name="module_zlib">zlib</a></h2>
<table>
<tbody><tr class="h"><th>ZLib Support</th><th>enabled</th></tr>
<tr><td class="e">Stream Wrapper </td><td class="v">compress.zlib:// </td></tr>
<tr><td class="e">Stream Filter </td><td class="v">zlib.inflate, zlib.deflate </td></tr>
<tr><td class="e">Compiled Version </td><td class="v">1.2.11 </td></tr>
<tr><td class="e">Linked Version </td><td class="v">1.2.11 </td></tr>
</tbody></table>
<table>
<tbody><tr class="h"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>
<tr><td class="e">zlib.output_compression</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">zlib.output_compression_level</td><td class="v">-1</td><td class="v">-1</td></tr>
<tr><td class="e">zlib.output_handler</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
</tbody></table>
<h2>Additional Modules</h2>
<table>
<tbody><tr class="h"><th>Module Name</th></tr>
</tbody></table>
<h2>Environment</h2>
<table>
<tbody><tr class="h"><th>Variable</th><th>Value</th></tr>
<tr><td class="e">OWNCLOUD_DOMAIN </td><td class="v">badowncloud:8080 </td></tr>
<tr><td class="e">OWNCLOUD_MAX_EXECUTION_TIME </td><td class="v">3600 </td></tr>
<tr><td class="e">OWNCLOUD_ALLOW_USER_TO_CHANGE_DISPLAY_NAME </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_ADMIN_USERNAME </td><td class="v">admin </td></tr>
<tr><td class="e">OWNCLOUD_DB_NAME </td><td class="v">owncloud </td></tr>
<tr><td class="e">OWNCLOUD_MAIL_SMTP_SECURE </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_OBJECTSTORE_BUCKET </td><td class="v">owncloud </td></tr>
<tr><td class="e">APACHE_SERVER_SIGNATURE </td><td class="v">Off </td></tr>
<tr><td class="e">OWNCLOUD_SHARE_FOLDER </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_PREVIEW_OFFICE_CL_PARAMETERS </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_COMMENTS_MANAGER_FACTORY </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_OBJECTSTORE_PART_SIZE </td><td class="v">5242880 </td></tr>
<tr><td class="e">OWNCLOUD_PROXY_USERPWD </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_CIPHER </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">GOMPLATE_VERSION </td><td class="v">v3.11.4 </td></tr>
<tr><td class="e">HOSTNAME </td><td class="v">512e79b087c5 </td></tr>
<tr><td class="e">OWNCLOUD_FILELOCKING_TTL </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_REDIS_PORT </td><td class="v">6379 </td></tr>
<tr><td class="e">APACHE_HOSTNAME_LOOKUPS </td><td class="v">Off </td></tr>
<tr><td class="e">OWNCLOUD_MYSQL_UTF8MB4 </td><td class="v">true </td></tr>
<tr><td class="e">OWNCLOUD_POST_CRONJOB_PATH </td><td class="v">/etc/post_cronjob.d </td></tr>
<tr><td class="e">APACHE_DOCUMENT_ROOT </td><td class="v">/var/www/owncloud </td></tr>
<tr><td class="e">OWNCLOUD_ENABLE_PREVIEWS </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">SHLVL </td><td class="v">0 </td></tr>
<tr><td class="e">OWNCLOUD_SESSION_SAVE_PATH </td><td class="v">/mnt/data/sessions </td></tr>
<tr><td class="e">HOME </td><td class="v">/root </td></tr>
<tr><td class="e">APACHE_ERROR_LOG </td><td class="v">/dev/stderr </td></tr>
<tr><td class="e">OWNCLOUD_VOLUME_APPS </td><td class="v">/mnt/data/apps </td></tr>
<tr><td class="e">OWNCLOUD_SESSION_KEEPALIVE </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_DEFAULT_APP </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_ENABLED_PREVIEW_PROVIDERS </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_DB_USERNAME </td><td class="v">owncloud </td></tr>
<tr><td class="e">OWNCLOUD_OBJECTSTORE_CLASS </td><td class="v">OCA\Files_Primary_S3\S3Storage </td></tr>
<tr><td class="e">OWNCLOUD_OBJECTSTORE_ENABLED </td><td class="v">false </td></tr>
<tr><td class="e">APACHE_ACCESS_LOG </td><td class="v">/dev/stdout </td></tr>
<tr><td class="e">OWNCLOUD_OBJECTSTORE_REGION </td><td class="v">us-east-1 </td></tr>
<tr><td class="e">OWNCLOUD_SHARING_FEDERATION_ALLOW_HTTP_FALLBACK </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_OBJECTSTORE_ENDPOINT </td><td class="v">s3-us-east-1.amazonaws.com </td></tr>
<tr><td class="e">OWNCLOUD_MAIL_SMTP_AUTH </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_REDIS_SESSION_LOCK_RETRIES </td><td class="v">750 </td></tr>
<tr><td class="e">OWNCLOUD_OBJECTSTORE_CONCURRENCY </td><td class="v">3 </td></tr>
<tr><td class="e">OWNCLOUD_CACHE_CHUNK_GC_TTL </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_REDIS_DB </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">APACHE_KEEP_ALIVE </td><td class="v">On </td></tr>
<tr><td class="e">OWNCLOUD_MAIL_FROM_ADDRESS </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_TOKEN_AUTH_ENFORCED </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_UPGRADE_AUTOMATIC_APP_UPDATES </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_BLACKLISTED_FILES </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_OBJECTSTORE_SECRET </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_KNOWLEDGEBASE_ENABLED </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_INTEGRITY_EXCLUDED_FILES </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_LOGIN_ALTERNATIVES </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">APACHE_RUN_DIR </td><td class="v">/var/run/apache2 </td></tr>
<tr><td class="e">OWNCLOUD_MARKETPLACE_CA </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_DEFAULT_LANGUAGE </td><td class="v">en </td></tr>
<tr><td class="e">OWNCLOUD_DAV_CHUNK_BASE_DIR </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_CORS_ALLOWED_DOMAINS </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">APACHE_PID_FILE </td><td class="v">/var/run/apache2/apache2.pid </td></tr>
<tr><td class="e">OWNCLOUD_MAINTENANCE </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_PRE_SERVER_PATH </td><td class="v">/etc/pre_server.d </td></tr>
<tr><td class="e">APACHE_MAX_KEEP_ALIVE_REQUESTS </td><td class="v">100 </td></tr>
<tr><td class="e">OWNCLOUD_APPSTORE_URL </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_MEMCACHED_STARTUP_TIMEOUT </td><td class="v">180 </td></tr>
<tr><td class="e">OWNCLOUD_HAS_INTERNET_CONNECTION </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_REMEMBER_LOGIN_COOKIE_LIFETIME </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_LOG_FILE </td><td class="v">/mnt/data/files/owncloud.log </td></tr>
<tr><td class="e">OWNCLOUD_LICENSE_KEY </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_INTEGRITY_IGNORE_MISSING_APP_SIGNATURE </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_LOG_ROTATE_SIZE </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_OPERATION_MODE </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">APACHE_SERVER_TOKENS </td><td class="v">Prod </td></tr>
<tr><td class="e">OWNCLOUD_FILESYSTEM_CHECK_CHANGES </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_CROND_ENABLED </td><td class="v">true </td></tr>
<tr><td class="e">OWNCLOUD_SECRET </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_HASHING_COST </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_SESSION_LIFETIME </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_REDIS_ENABLED </td><td class="v">true </td></tr>
<tr><td class="e">OWNCLOUD_SUB_URL </td><td class="v">/ </td></tr>
<tr><td class="e">OWNCLOUD_POST_INSTALL_PATH </td><td class="v">/etc/post_install.d </td></tr>
<tr><td class="e">OWNCLOUD_OVERWRITE_WEBROOT </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_SKIP_CHMOD </td><td class="v">false </td></tr>
<tr><td class="e">OWNCLOUD_LOG_DATE_FORMAT </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_SINGLEUSER </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_FILELOCKING_ENABLED </td><td class="v">true </td></tr>
<tr><td class="e">OWNCLOUD_DB_PREFIX </td><td class="v">oc_ </td></tr>
<tr><td class="e">OWNCLOUD_OVERWRITE_PROTOCOL </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_VOLUME_SESSIONS </td><td class="v">/mnt/data/sessions </td></tr>
<tr><td class="e">OWNCLOUD_MAIL_SMTP_PASSWORD </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_PROXY </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_REDIS_SESSION_LOCK_WAIT_TIME </td><td class="v">20000 </td></tr>
<tr><td class="e">OWNCLOUD_CSRF_DISABLED </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_ERRORLOG_LOCATION </td><td class="v">/dev/stderr </td></tr>
<tr><td class="e">OWNCLOUD_SHOW_SERVER_HOSTNAME </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">TERM </td><td class="v">xterm </td></tr>
<tr><td class="e">OWNCLOUD_ENABLE_OIDC_REWRITE_URL </td><td class="v">false </td></tr>
<tr><td class="e">OWNCLOUD_ADMIN_PASSWORD </td><td class="v">admin </td></tr>
<tr><td class="e">OWNCLOUD_SESSION_SAVE_HANDLER </td><td class="v">files </td></tr>
<tr><td class="e">OWNCLOUD_ACCESSLOG_LOCATION </td><td class="v">/dev/stdout </td></tr>
<tr><td class="e">OWNCLOUD_MEMCACHED_HOST </td><td class="v">memcached </td></tr>
<tr><td class="e">OWNCLOUD_MAIL_SMTP_TIMEOUT </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">APACHE_ADD_DEFAULT_CHARSET </td><td class="v">UTF-8 </td></tr>
<tr><td class="e">OWNCLOUD_VERSION_HIDE </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_VOLUME_CONFIG </td><td class="v">/mnt/data/config </td></tr>
<tr><td class="e">OWNCLOUD_PREVIEW_MAX_FILESIZE_IMAGE </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">APACHE_TRACE_ENABLE </td><td class="v">Off </td></tr>
<tr><td class="e">OWNCLOUD_MAIL_SMTP_HOST </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">WAIT_FOR_VERSION </td><td class="v">v1.1.0 </td></tr>
<tr><td class="e">OWNCLOUD_MAX_INPUT_TIME </td><td class="v">3600 </td></tr>
<tr><td class="e">OWNCLOUD_SESSION_FORCED_LOGOUT_TIMEOUT </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">PATH </td><td class="v">/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin </td></tr>
<tr><td class="e">OWNCLOUD_EXCLUDED_DIRECTORIES </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_APPS_DEPRECATED </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_OVERWRITE_HOST </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_BACKGROUND_MODE </td><td class="v">cron </td></tr>
<tr><td class="e">OWNCLOUD_SMB_LOGGING_ENABLE </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_SYSTEMTAGS_MANAGER_FACTORY </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_MAIL_SMTP_DEBUG </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_OVERWRITE_COND_ADDR </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_VOLUME_ROOT </td><td class="v">/mnt/data </td></tr>
<tr><td class="e">OWNCLOUD_UPDATER_SERVER_URL </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_UPDATE_CHECKER </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_OBJECTSTORE_KEY </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_OVERWRITE_CLI_URL </td><td class="v">http://badowncloud:8080/ </td></tr>
<tr><td class="e">OWNCLOUD_MEMCACHED_OPTIONS </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_ENABLE_AVATARS </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_TRUSTED_PROXIES </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_OBJECTSTORE_PATHSTYLE </td><td class="v">false </td></tr>
<tr><td class="e">OWNCLOUD_LOG_LEVEL </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_HTTP_COOKIE_SAMESITE </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">APACHE_LOCK_DIR </td><td class="v">/var/lock/apache2 </td></tr>
<tr><td class="e">OWNCLOUD_CACHE_PATH </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_REDIS_SESSION_LOCKING_ENABLED </td><td class="v">1 </td></tr>
<tr><td class="e">APACHE_SERVER_ADMIN </td><td class="v">webmaster@localhost </td></tr>
<tr><td class="e">RETRY_VERSION </td><td class="v">v2.0.0 </td></tr>
<tr><td class="e">LANG </td><td class="v">C </td></tr>
<tr><td class="e">OWNCLOUD_PREVIEW_MAX_SCALE_FACTOR </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_MAX_FILESIZE_ANIMATED_GIFS_PUBLIC_SHARING </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">APACHE_ACCESS_FILE_NAME </td><td class="v">.htaccess </td></tr>
<tr><td class="e">OWNCLOUD_ENTRYPOINT_INITIALIZED </td><td class="v">true </td></tr>
<tr><td class="e">OWNCLOUD_SKELETON_DIRECTORY </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_DB_PASSWORD </td><td class="v">owncloud </td></tr>
<tr><td class="e">OWNCLOUD_MAX_UPLOAD </td><td class="v">20G </td></tr>
<tr><td class="e">OWNCLOUD_LOST_PASSWORD_LINK </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_PREVIEW_LIBREOFFICE_PATH </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_ACCOUNTS_ENABLE_MEDIAL_SEARCH </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_FILESYSTEM_CACHE_READONLY </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_MEMCACHED_PORT </td><td class="v">11211 </td></tr>
<tr><td class="e">DEBIAN_FRONTEND </td><td class="v">noninteractive </td></tr>
<tr><td class="e">OWNCLOUD_DEFAULT_SOCKET_TIMEOUT </td><td class="v">60 </td></tr>
<tr><td class="e">OWNCLOUD_MAIL_SMTP_PORT </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">APACHE_LOG_LEVEL </td><td class="v">trace6 </td></tr>
<tr><td class="e">OWNCLOUD_CHECK_FOR_WORKING_WELLKNOWN_SETUP </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_OBJECTSTORE_VERSION </td><td class="v">2006-03-01 </td></tr>
<tr><td class="e">OWNCLOUD_PRE_CRONJOB_PATH </td><td class="v">/etc/pre_cronjob.d </td></tr>
<tr><td class="e">APACHE_LISTEN </td><td class="v">8080 </td></tr>
<tr><td class="e">OWNCLOUD_QUOTA_INCLUDE_EXTERNAL_STORAGE </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_APPSTORE_ENABLED </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_DB_TIMEOUT </td><td class="v">180 </td></tr>
<tr><td class="e">OWNCLOUD_FORWARDED_FOR_HEADERS </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">APACHE_RUN_GROUP </td><td class="v">www-data </td></tr>
<tr><td class="e">APACHE_RUN_USER </td><td class="v">www-data </td></tr>
<tr><td class="e">APACHE_ENTRYPOINT_INITIALIZED </td><td class="v">true </td></tr>
<tr><td class="e">OWNCLOUD_DB_HOST </td><td class="v">mariadb:3306 </td></tr>
<tr><td class="e">APACHE_SERVER_NAME </td><td class="v">localhost </td></tr>
<tr><td class="e">OWNCLOUD_POST_SERVER_PATH </td><td class="v">/etc/post_server.d </td></tr>
<tr><td class="e">OWNCLOUD_PREVIEW_MAX_X </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_VERSIONS_RETENTION_OBLIGATION </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_FILES_EXTERNAL_ALLOW_NEW_LOCAL </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_SHARING_MANAGER_FACTORY </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_APPS_INSTALL </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_PROTOCOL </td><td class="v">http </td></tr>
<tr><td class="e">APACHE_LOG_FORMAT </td><td class="v">combined </td></tr>
<tr><td class="e">OWNCLOUD_MAIL_SMTP_NAME </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_REDIS_STARTUP_TIMEOUT </td><td class="v">180 </td></tr>
<tr><td class="e">OWNCLOUD_PREVIEW_MAX_Y </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_VOLUME_FILES </td><td class="v">/mnt/data/files </td></tr>
<tr><td class="e">OWNCLOUD_TRUSTED_DOMAINS </td><td class="v">badowncloud </td></tr>
<tr><td class="e">OWNCLOUD_CRON_LOG </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_TRASHBIN_PURGE_LIMIT </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">APACHE_KEEP_ALIVE_TIMEOUT </td><td class="v">5 </td></tr>
<tr><td class="e">OWNCLOUD_USER_SEARCH_MIN_LENGTH </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_ENABLE_CERTIFICATE_MANAGEMENT </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_LOG_TIMEZONE </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_CROND_SCHEDULE </td><td class="v">*/1 * * * * </td></tr>
<tr><td class="e">PWD </td><td class="v">/var/www/owncloud </td></tr>
<tr><td class="e">OWNCLOUD_DAV_ENABLE_ASYNC </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_DB_TYPE </td><td class="v">mysql </td></tr>
<tr><td class="e">OWNCLOUD_REDIS_PASSWORD </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_TEMP_DIRECTORY </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_APPS_DISABLE </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_APPS_INSTALL_MAJOR </td><td class="v">false </td></tr>
<tr><td class="e">OWNCLOUD_MOUNT_FILE </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_MAIL_SMTP_MODE </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_MARKETPLACE_KEY </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_DB_FAIL </td><td class="v">true </td></tr>
<tr><td class="e">OWNCLOUD_SQLITE_JOURNAL_MODE </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_APPS_ENABLE </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_MEMCACHE_LOCAL </td><td class="v">\OC\Memcache\APCu </td></tr>
<tr><td class="e">OWNCLOUD_MEMCACHE_LOCKING </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_REDIS_TIMEOUT </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_MAIL_DOMAIN </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_MAIL_SMTP_AUTH_TYPE </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_REDIS_HOST </td><td class="v">redis </td></tr>
<tr><td class="e">OWNCLOUD_MEMCACHED_ENABLED </td><td class="v">false </td></tr>
<tr><td class="e">OWNCLOUD_DEBUG </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_PART_FILE_IN_STORAGE </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_APPS_UNINSTALL </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">APACHE_TIMEOUT </td><td class="v">300 </td></tr>
<tr><td class="e">OWNCLOUD_PRE_INSTALL_PATH </td><td class="v">/etc/pre_install.d </td></tr>
<tr><td class="e">OWNCLOUD_SKIP_CHOWN </td><td class="v">false </td></tr>
<tr><td class="e">OWNCLOUD_LICENSE_CLASS </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_MINIMUM_SUPPORTED_DESKTOP_VERSION </td><td class="v"><i>no value</i> </td></tr>
<tr><td class="e">OWNCLOUD_HTACCESS_REWRITE_BASE </td><td class="v">/ </td></tr>
<tr><td class="e">OWNCLOUD_TRASHBIN_RETENTION_OBLIGATION </td><td class="v"><i>no value</i> </td></tr>
</tbody></table>
<h2>PHP Variables</h2>
<table>
<tbody><tr class="h"><th>Variable</th><th>Value</th></tr>
<tr><td class="e">$_COOKIE['oce6x9uqffor']</td><td class="v">vi3opkotft2oo209cj7j03dvmi</td></tr>
<tr><td class="e">$_COOKIE['oc_sessionPassphrase']</td><td class="v">LT7Az1LZ87Fg5MlFkb0811zpzhYGsfike/2rfSrL8fBxFOniCzbhqowdPbg9V8GmcF9H7duEscB81sPKVdKOQokR4MatJDdxs4eHWrdP+kAIena7S+4Y2+JLQN+X02I9</td></tr>
<tr><td class="e">$_SERVER['HTTP_AUTHORIZATION']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_SERVER['modHeadersAvailable']</td><td class="v">true</td></tr>
<tr><td class="e">$_SERVER['htaccessWorking']</td><td class="v">true</td></tr>
<tr><td class="e">$_SERVER['front_controller_active']</td><td class="v">true</td></tr>
<tr><td class="e">$_SERVER['HTTP_HOST']</td><td class="v">badowncloud:8080</td></tr>
<tr><td class="e">$_SERVER['HTTP_CONNECTION']</td><td class="v">keep-alive</td></tr>
<tr><td class="e">$_SERVER['HTTP_DNT']</td><td class="v">1</td></tr>
<tr><td class="e">$_SERVER['HTTP_UPGRADE_INSECURE_REQUESTS']</td><td class="v">1</td></tr>
<tr><td class="e">$_SERVER['HTTP_USER_AGENT']</td><td class="v">Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36</td></tr>
<tr><td class="e">$_SERVER['HTTP_ACCEPT']</td><td class="v">text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7</td></tr>
<tr><td class="e">$_SERVER['HTTP_ACCEPT_ENCODING']</td><td class="v">gzip, deflate</td></tr>
<tr><td class="e">$_SERVER['HTTP_ACCEPT_LANGUAGE']</td><td class="v">en-US,en;q=0.9</td></tr>
<tr><td class="e">$_SERVER['HTTP_COOKIE']</td><td class="v">oce6x9uqffor=vi3opkotft2oo209cj7j03dvmi; oc_sessionPassphrase=LT7Az1LZ87Fg5MlFkb0811zpzhYGsfike%2F2rfSrL8fBxFOniCzbhqowdPbg9V8GmcF9H7duEscB81sPKVdKOQokR4MatJDdxs4eHWrdP%2BkAIena7S%2B4Y2%2BJLQN%2BX02I9</td></tr>
<tr><td class="e">$_SERVER['PATH']</td><td class="v">/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin</td></tr>
<tr><td class="e">$_SERVER['SERVER_SIGNATURE']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_SERVER['SERVER_SOFTWARE']</td><td class="v">Apache</td></tr>
<tr><td class="e">$_SERVER['SERVER_NAME']</td><td class="v">badowncloud</td></tr>
<tr><td class="e">$_SERVER['SERVER_ADDR']</td><td class="v">172.18.0.4</td></tr>
<tr><td class="e">$_SERVER['SERVER_PORT']</td><td class="v">8080</td></tr>
<tr><td class="e">$_SERVER['REMOTE_ADDR']</td><td class="v">192.168.56.1</td></tr>
<tr><td class="e">$_SERVER['DOCUMENT_ROOT']</td><td class="v">/var/www/owncloud</td></tr>
<tr><td class="e">$_SERVER['REQUEST_SCHEME']</td><td class="v">http</td></tr>
<tr><td class="e">$_SERVER['CONTEXT_PREFIX']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_SERVER['CONTEXT_DOCUMENT_ROOT']</td><td class="v">/var/www/owncloud</td></tr>
<tr><td class="e">$_SERVER['SERVER_ADMIN']</td><td class="v">webmaster@localhost</td></tr>
<tr><td class="e">$_SERVER['SCRIPT_FILENAME']</td><td class="v">/var/www/owncloud/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php</td></tr>
<tr><td class="e">$_SERVER['REMOTE_PORT']</td><td class="v">65495</td></tr>
<tr><td class="e">$_SERVER['GATEWAY_INTERFACE']</td><td class="v">CGI/1.1</td></tr>
<tr><td class="e">$_SERVER['SERVER_PROTOCOL']</td><td class="v">HTTP/1.1</td></tr>
<tr><td class="e">$_SERVER['REQUEST_METHOD']</td><td class="v">GET</td></tr>
<tr><td class="e">$_SERVER['QUERY_STRING']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_SERVER['REQUEST_URI']</td><td class="v">//apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php/</td></tr>
<tr><td class="e">$_SERVER['SCRIPT_NAME']</td><td class="v">/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php</td></tr>
<tr><td class="e">$_SERVER['PATH_INFO']</td><td class="v">/</td></tr>
<tr><td class="e">$_SERVER['PATH_TRANSLATED']</td><td class="v">/var/www/owncloud/index.php</td></tr>
<tr><td class="e">$_SERVER['PHP_SELF']</td><td class="v">/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php/</td></tr>
<tr><td class="e">$_SERVER['REQUEST_TIME_FLOAT']</td><td class="v">1702890991.163</td></tr>
<tr><td class="e">$_SERVER['REQUEST_TIME']</td><td class="v">1702890991</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_DOMAIN']</td><td class="v">badowncloud:8080</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_MAX_EXECUTION_TIME']</td><td class="v">3600</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_ALLOW_USER_TO_CHANGE_DISPLAY_NAME']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_ADMIN_USERNAME']</td><td class="v">admin</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_DB_NAME']</td><td class="v">owncloud</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_MAIL_SMTP_SECURE']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_OBJECTSTORE_BUCKET']</td><td class="v">owncloud</td></tr>
<tr><td class="e">$_ENV['APACHE_SERVER_SIGNATURE']</td><td class="v">Off</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_SHARE_FOLDER']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_PREVIEW_OFFICE_CL_PARAMETERS']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_COMMENTS_MANAGER_FACTORY']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_OBJECTSTORE_PART_SIZE']</td><td class="v">5242880</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_PROXY_USERPWD']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_CIPHER']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['GOMPLATE_VERSION']</td><td class="v">v3.11.4</td></tr>
<tr><td class="e">$_ENV['HOSTNAME']</td><td class="v">512e79b087c5</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_FILELOCKING_TTL']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_REDIS_PORT']</td><td class="v">6379</td></tr>
<tr><td class="e">$_ENV['APACHE_HOSTNAME_LOOKUPS']</td><td class="v">Off</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_MYSQL_UTF8MB4']</td><td class="v">true</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_POST_CRONJOB_PATH']</td><td class="v">/etc/post_cronjob.d</td></tr>
<tr><td class="e">$_ENV['APACHE_DOCUMENT_ROOT']</td><td class="v">/var/www/owncloud</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_ENABLE_PREVIEWS']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['SHLVL']</td><td class="v">0</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_SESSION_SAVE_PATH']</td><td class="v">/mnt/data/sessions</td></tr>
<tr><td class="e">$_ENV['HOME']</td><td class="v">/root</td></tr>
<tr><td class="e">$_ENV['APACHE_ERROR_LOG']</td><td class="v">/dev/stderr</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_VOLUME_APPS']</td><td class="v">/mnt/data/apps</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_SESSION_KEEPALIVE']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_DEFAULT_APP']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_ENABLED_PREVIEW_PROVIDERS']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_DB_USERNAME']</td><td class="v">owncloud</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_OBJECTSTORE_CLASS']</td><td class="v">OCA\Files_Primary_S3\S3Storage</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_OBJECTSTORE_ENABLED']</td><td class="v">false</td></tr>
<tr><td class="e">$_ENV['APACHE_ACCESS_LOG']</td><td class="v">/dev/stdout</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_OBJECTSTORE_REGION']</td><td class="v">us-east-1</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_SHARING_FEDERATION_ALLOW_HTTP_FALLBACK']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_OBJECTSTORE_ENDPOINT']</td><td class="v">s3-us-east-1.amazonaws.com</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_MAIL_SMTP_AUTH']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_REDIS_SESSION_LOCK_RETRIES']</td><td class="v">750</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_OBJECTSTORE_CONCURRENCY']</td><td class="v">3</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_CACHE_CHUNK_GC_TTL']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_REDIS_DB']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['APACHE_KEEP_ALIVE']</td><td class="v">On</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_MAIL_FROM_ADDRESS']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_TOKEN_AUTH_ENFORCED']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_UPGRADE_AUTOMATIC_APP_UPDATES']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_BLACKLISTED_FILES']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_OBJECTSTORE_SECRET']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_KNOWLEDGEBASE_ENABLED']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_INTEGRITY_EXCLUDED_FILES']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_LOGIN_ALTERNATIVES']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['APACHE_RUN_DIR']</td><td class="v">/var/run/apache2</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_MARKETPLACE_CA']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_DEFAULT_LANGUAGE']</td><td class="v">en</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_DAV_CHUNK_BASE_DIR']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_CORS_ALLOWED_DOMAINS']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['APACHE_PID_FILE']</td><td class="v">/var/run/apache2/apache2.pid</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_MAINTENANCE']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_PRE_SERVER_PATH']</td><td class="v">/etc/pre_server.d</td></tr>
<tr><td class="e">$_ENV['APACHE_MAX_KEEP_ALIVE_REQUESTS']</td><td class="v">100</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_APPSTORE_URL']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_MEMCACHED_STARTUP_TIMEOUT']</td><td class="v">180</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_HAS_INTERNET_CONNECTION']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_REMEMBER_LOGIN_COOKIE_LIFETIME']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_LOG_FILE']</td><td class="v">/mnt/data/files/owncloud.log</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_LICENSE_KEY']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_INTEGRITY_IGNORE_MISSING_APP_SIGNATURE']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_LOG_ROTATE_SIZE']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_OPERATION_MODE']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['APACHE_SERVER_TOKENS']</td><td class="v">Prod</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_FILESYSTEM_CHECK_CHANGES']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_CROND_ENABLED']</td><td class="v">true</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_SECRET']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_HASHING_COST']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_SESSION_LIFETIME']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_REDIS_ENABLED']</td><td class="v">true</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_SUB_URL']</td><td class="v">/</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_POST_INSTALL_PATH']</td><td class="v">/etc/post_install.d</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_OVERWRITE_WEBROOT']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_SKIP_CHMOD']</td><td class="v">false</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_LOG_DATE_FORMAT']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_SINGLEUSER']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_FILELOCKING_ENABLED']</td><td class="v">true</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_DB_PREFIX']</td><td class="v">oc_</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_OVERWRITE_PROTOCOL']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_VOLUME_SESSIONS']</td><td class="v">/mnt/data/sessions</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_MAIL_SMTP_PASSWORD']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_PROXY']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_REDIS_SESSION_LOCK_WAIT_TIME']</td><td class="v">20000</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_CSRF_DISABLED']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_ERRORLOG_LOCATION']</td><td class="v">/dev/stderr</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_SHOW_SERVER_HOSTNAME']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['TERM']</td><td class="v">xterm</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_ENABLE_OIDC_REWRITE_URL']</td><td class="v">false</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_ADMIN_PASSWORD']</td><td class="v">admin</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_SESSION_SAVE_HANDLER']</td><td class="v">files</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_ACCESSLOG_LOCATION']</td><td class="v">/dev/stdout</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_MEMCACHED_HOST']</td><td class="v">memcached</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_MAIL_SMTP_TIMEOUT']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['APACHE_ADD_DEFAULT_CHARSET']</td><td class="v">UTF-8</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_VERSION_HIDE']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_VOLUME_CONFIG']</td><td class="v">/mnt/data/config</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_PREVIEW_MAX_FILESIZE_IMAGE']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['APACHE_TRACE_ENABLE']</td><td class="v">Off</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_MAIL_SMTP_HOST']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['WAIT_FOR_VERSION']</td><td class="v">v1.1.0</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_MAX_INPUT_TIME']</td><td class="v">3600</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_SESSION_FORCED_LOGOUT_TIMEOUT']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['PATH']</td><td class="v">/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_EXCLUDED_DIRECTORIES']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_APPS_DEPRECATED']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_OVERWRITE_HOST']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_BACKGROUND_MODE']</td><td class="v">cron</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_SMB_LOGGING_ENABLE']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_SYSTEMTAGS_MANAGER_FACTORY']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_MAIL_SMTP_DEBUG']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_OVERWRITE_COND_ADDR']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_VOLUME_ROOT']</td><td class="v">/mnt/data</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_UPDATER_SERVER_URL']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_UPDATE_CHECKER']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_OBJECTSTORE_KEY']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_OVERWRITE_CLI_URL']</td><td class="v">http://badowncloud:8080/</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_MEMCACHED_OPTIONS']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_ENABLE_AVATARS']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_TRUSTED_PROXIES']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_OBJECTSTORE_PATHSTYLE']</td><td class="v">false</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_LOG_LEVEL']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_HTTP_COOKIE_SAMESITE']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['APACHE_LOCK_DIR']</td><td class="v">/var/lock/apache2</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_CACHE_PATH']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_REDIS_SESSION_LOCKING_ENABLED']</td><td class="v">1</td></tr>
<tr><td class="e">$_ENV['APACHE_SERVER_ADMIN']</td><td class="v">webmaster@localhost</td></tr>
<tr><td class="e">$_ENV['RETRY_VERSION']</td><td class="v">v2.0.0</td></tr>
<tr><td class="e">$_ENV['LANG']</td><td class="v">C</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_PREVIEW_MAX_SCALE_FACTOR']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_MAX_FILESIZE_ANIMATED_GIFS_PUBLIC_SHARING']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['APACHE_ACCESS_FILE_NAME']</td><td class="v">.htaccess</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_ENTRYPOINT_INITIALIZED']</td><td class="v">true</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_SKELETON_DIRECTORY']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_DB_PASSWORD']</td><td class="v">owncloud</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_MAX_UPLOAD']</td><td class="v">20G</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_LOST_PASSWORD_LINK']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_PREVIEW_LIBREOFFICE_PATH']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_ACCOUNTS_ENABLE_MEDIAL_SEARCH']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_FILESYSTEM_CACHE_READONLY']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_MEMCACHED_PORT']</td><td class="v">11211</td></tr>
<tr><td class="e">$_ENV['DEBIAN_FRONTEND']</td><td class="v">noninteractive</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_DEFAULT_SOCKET_TIMEOUT']</td><td class="v">60</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_MAIL_SMTP_PORT']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['APACHE_LOG_LEVEL']</td><td class="v">trace6</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_CHECK_FOR_WORKING_WELLKNOWN_SETUP']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_OBJECTSTORE_VERSION']</td><td class="v">2006-03-01</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_PRE_CRONJOB_PATH']</td><td class="v">/etc/pre_cronjob.d</td></tr>
<tr><td class="e">$_ENV['APACHE_LISTEN']</td><td class="v">8080</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_QUOTA_INCLUDE_EXTERNAL_STORAGE']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_APPSTORE_ENABLED']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_DB_TIMEOUT']</td><td class="v">180</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_FORWARDED_FOR_HEADERS']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['APACHE_RUN_GROUP']</td><td class="v">www-data</td></tr>
<tr><td class="e">$_ENV['APACHE_RUN_USER']</td><td class="v">www-data</td></tr>
<tr><td class="e">$_ENV['APACHE_ENTRYPOINT_INITIALIZED']</td><td class="v">true</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_DB_HOST']</td><td class="v">mariadb:3306</td></tr>
<tr><td class="e">$_ENV['APACHE_SERVER_NAME']</td><td class="v">localhost</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_POST_SERVER_PATH']</td><td class="v">/etc/post_server.d</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_PREVIEW_MAX_X']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_VERSIONS_RETENTION_OBLIGATION']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_FILES_EXTERNAL_ALLOW_NEW_LOCAL']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_SHARING_MANAGER_FACTORY']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_APPS_INSTALL']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_PROTOCOL']</td><td class="v">http</td></tr>
<tr><td class="e">$_ENV['APACHE_LOG_FORMAT']</td><td class="v">combined</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_MAIL_SMTP_NAME']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_REDIS_STARTUP_TIMEOUT']</td><td class="v">180</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_PREVIEW_MAX_Y']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_VOLUME_FILES']</td><td class="v">/mnt/data/files</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_TRUSTED_DOMAINS']</td><td class="v">badowncloud</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_CRON_LOG']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_TRASHBIN_PURGE_LIMIT']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['APACHE_KEEP_ALIVE_TIMEOUT']</td><td class="v">5</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_USER_SEARCH_MIN_LENGTH']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_ENABLE_CERTIFICATE_MANAGEMENT']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_LOG_TIMEZONE']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_CROND_SCHEDULE']</td><td class="v">*/1 * * * *</td></tr>
<tr><td class="e">$_ENV['PWD']</td><td class="v">/var/www/owncloud</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_DAV_ENABLE_ASYNC']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_DB_TYPE']</td><td class="v">mysql</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_REDIS_PASSWORD']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_TEMP_DIRECTORY']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_APPS_DISABLE']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_APPS_INSTALL_MAJOR']</td><td class="v">false</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_MOUNT_FILE']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_MAIL_SMTP_MODE']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_MARKETPLACE_KEY']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_DB_FAIL']</td><td class="v">true</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_SQLITE_JOURNAL_MODE']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_APPS_ENABLE']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_MEMCACHE_LOCAL']</td><td class="v">\OC\Memcache\APCu</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_MEMCACHE_LOCKING']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_REDIS_TIMEOUT']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_MAIL_DOMAIN']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_MAIL_SMTP_AUTH_TYPE']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_REDIS_HOST']</td><td class="v">redis</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_MEMCACHED_ENABLED']</td><td class="v">false</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_DEBUG']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_PART_FILE_IN_STORAGE']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_APPS_UNINSTALL']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['APACHE_TIMEOUT']</td><td class="v">300</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_PRE_INSTALL_PATH']</td><td class="v">/etc/pre_install.d</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_SKIP_CHOWN']</td><td class="v">false</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_LICENSE_CLASS']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_MINIMUM_SUPPORTED_DESKTOP_VERSION']</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_HTACCESS_REWRITE_BASE']</td><td class="v">/</td></tr>
<tr><td class="e">$_ENV['OWNCLOUD_TRASHBIN_RETENTION_OBLIGATION']</td><td class="v"><i>no value</i></td></tr>
</tbody></table>
<hr>
<h1>PHP Credits</h1>
<table>
<tbody><tr class="h"><th>PHP Group</th></tr>
<tr><td class="e">Thies C. Arntzen, Stig Bakken, Shane Caraveo, Andi Gutmans, Rasmus Lerdorf, Sam Ruby, Sascha Schumann, Zeev Suraski, Jim Winstead, Andrei Zmievski </td></tr>
</tbody></table>
<table>
<tbody><tr class="h"><th>Language Design &amp; Concept</th></tr>
<tr><td class="e">Andi Gutmans, Rasmus Lerdorf, Zeev Suraski, Marcus Boerger </td></tr>
</tbody></table>
<table>
<tbody><tr class="h"><th colspan="2">PHP Authors</th></tr>
<tr class="h"><th>Contribution</th><th>Authors</th></tr>
<tr><td class="e">Zend Scripting Language Engine </td><td class="v">Andi Gutmans, Zeev Suraski, Stanislav Malyshev, Marcus Boerger, Dmitry Stogov, Xinchen Hui, Nikita Popov </td></tr>
<tr><td class="e">Extension Module API </td><td class="v">Andi Gutmans, Zeev Suraski, Andrei Zmievski </td></tr>
<tr><td class="e">UNIX Build and Modularization </td><td class="v">Stig Bakken, Sascha Schumann, Jani Taskinen, Peter Kokot </td></tr>
<tr><td class="e">Windows Support </td><td class="v">Shane Caraveo, Zeev Suraski, Wez Furlong, Pierre-Alain Joye, Anatol Belski, Kalle Sommer Nielsen </td></tr>
<tr><td class="e">Server API (SAPI) Abstraction Layer </td><td class="v">Andi Gutmans, Shane Caraveo, Zeev Suraski </td></tr>
<tr><td class="e">Streams Abstraction Layer </td><td class="v">Wez Furlong, Sara Golemon </td></tr>
<tr><td class="e">PHP Data Objects Layer </td><td class="v">Wez Furlong, Marcus Boerger, Sterling Hughes, George Schlossnagle, Ilia Alshanetsky </td></tr>
<tr><td class="e">Output Handler </td><td class="v">Zeev Suraski, Thies C. Arntzen, Marcus Boerger, Michael Wallner </td></tr>
<tr><td class="e">Consistent 64 bit support </td><td class="v">Anthony Ferrara, Anatol Belski </td></tr>
</tbody></table>
<table>
<tbody><tr class="h"><th colspan="2">SAPI Modules</th></tr>
<tr class="h"><th>Contribution</th><th>Authors</th></tr>
<tr><td class="e">Apache 2.0 Handler </td><td class="v">Ian Holsman, Justin Erenkrantz (based on Apache 2.0 Filter code) </td></tr>
<tr><td class="e">CGI / FastCGI </td><td class="v">Rasmus Lerdorf, Stig Bakken, Shane Caraveo, Dmitry Stogov </td></tr>
<tr><td class="e">CLI </td><td class="v">Edin Kadribasic, Marcus Boerger, Johannes Schlueter, Moriyoshi Koizumi, Xinchen Hui </td></tr>
<tr><td class="e">Embed </td><td class="v">Edin Kadribasic </td></tr>
<tr><td class="e">FastCGI Process Manager </td><td class="v">Andrei Nigmatulin, dreamcat4, Antony Dovgal, Jerome Loyet </td></tr>
<tr><td class="e">litespeed </td><td class="v">George Wang </td></tr>
<tr><td class="e">phpdbg </td><td class="v">Felipe Pena, Joe Watkins, Bob Weinand </td></tr>
</tbody></table>
<table>
<tbody><tr class="h"><th colspan="2">Module Authors</th></tr>
<tr class="h"><th>Module</th><th>Authors</th></tr>
<tr><td class="e">BC Math </td><td class="v">Andi Gutmans </td></tr>
<tr><td class="e">Bzip2 </td><td class="v">Sterling Hughes </td></tr>
<tr><td class="e">Calendar </td><td class="v">Shane Caraveo, Colin Viebrock, Hartmut Holzgraefe, Wez Furlong </td></tr>
<tr><td class="e">COM and .Net </td><td class="v">Wez Furlong </td></tr>
<tr><td class="e">ctype </td><td class="v">Hartmut Holzgraefe </td></tr>
<tr><td class="e">cURL </td><td class="v">Sterling Hughes </td></tr>
<tr><td class="e">Date/Time Support </td><td class="v">Derick Rethans </td></tr>
<tr><td class="e">DB-LIB (MS SQL, Sybase) </td><td class="v">Wez Furlong, Frank M. Kromann, Adam Baratz </td></tr>
<tr><td class="e">DBA </td><td class="v">Sascha Schumann, Marcus Boerger </td></tr>
<tr><td class="e">DOM </td><td class="v">Christian Stocker, Rob Richards, Marcus Boerger </td></tr>
<tr><td class="e">enchant </td><td class="v">Pierre-Alain Joye, Ilia Alshanetsky </td></tr>
<tr><td class="e">EXIF </td><td class="v">Rasmus Lerdorf, Marcus Boerger </td></tr>
<tr><td class="e">FFI </td><td class="v">Dmitry Stogov </td></tr>
<tr><td class="e">fileinfo </td><td class="v">Ilia Alshanetsky, Pierre Alain Joye, Scott MacVicar, Derick Rethans, Anatol Belski </td></tr>
<tr><td class="e">Firebird driver for PDO </td><td class="v">Ard Biesheuvel </td></tr>
<tr><td class="e">FTP </td><td class="v">Stefan Esser, Andrew Skalski </td></tr>
<tr><td class="e">GD imaging </td><td class="v">Rasmus Lerdorf, Stig Bakken, Jim Winstead, Jouni Ahto, Ilia Alshanetsky, Pierre-Alain Joye, Marcus Boerger </td></tr>
<tr><td class="e">GetText </td><td class="v">Alex Plotnick </td></tr>
<tr><td class="e">GNU GMP support </td><td class="v">Stanislav Malyshev </td></tr>
<tr><td class="e">Iconv </td><td class="v">Rui Hirokawa, Stig Bakken, Moriyoshi Koizumi </td></tr>
<tr><td class="e">IMAP </td><td class="v">Rex Logan, Mark Musone, Brian Wang, Kaj-Michael Lang, Antoni Pamies Olive, Rasmus Lerdorf, Andrew Skalski, Chuck Hagenbuch, Daniel R Kalowsky </td></tr>
<tr><td class="e">Input Filter </td><td class="v">Rasmus Lerdorf, Derick Rethans, Pierre-Alain Joye, Ilia Alshanetsky </td></tr>
<tr><td class="e">Internationalization </td><td class="v">Ed Batutis, Vladimir Iordanov, Dmitry Lakhtyuk, Stanislav Malyshev, Vadim Savchuk, Kirti Velankar </td></tr>
<tr><td class="e">JSON </td><td class="v">Jakub Zelenka, Omar Kilani, Scott MacVicar </td></tr>
<tr><td class="e">LDAP </td><td class="v">Amitay Isaacs, Eric Warnke, Rasmus Lerdorf, Gerrit Thomson, Stig Venaas </td></tr>
<tr><td class="e">LIBXML </td><td class="v">Christian Stocker, Rob Richards, Marcus Boerger, Wez Furlong, Shane Caraveo </td></tr>
<tr><td class="e">Multibyte String Functions </td><td class="v">Tsukada Takuya, Rui Hirokawa </td></tr>
<tr><td class="e">MySQL driver for PDO </td><td class="v">George Schlossnagle, Wez Furlong, Ilia Alshanetsky, Johannes Schlueter </td></tr>
<tr><td class="e">MySQLi </td><td class="v">Zak Greant, Georg Richter, Andrey Hristov, Ulf Wendel </td></tr>
<tr><td class="e">MySQLnd </td><td class="v">Andrey Hristov, Ulf Wendel, Georg Richter, Johannes Schlüter </td></tr>
<tr><td class="e">OCI8 </td><td class="v">Stig Bakken, Thies C. Arntzen, Andy Sautins, David Benson, Maxim Maletsky, Harald Radi, Antony Dovgal, Andi Gutmans, Wez Furlong, Christopher Jones, Oracle Corporation </td></tr>
<tr><td class="e">ODBC driver for PDO </td><td class="v">Wez Furlong </td></tr>
<tr><td class="e">ODBC </td><td class="v">Stig Bakken, Andreas Karajannis, Frank M. Kromann, Daniel R. Kalowsky </td></tr>
<tr><td class="e">Opcache </td><td class="v">Andi Gutmans, Zeev Suraski, Stanislav Malyshev, Dmitry Stogov, Xinchen Hui </td></tr>
<tr><td class="e">OpenSSL </td><td class="v">Stig Venaas, Wez Furlong, Sascha Kettler, Scott MacVicar </td></tr>
<tr><td class="e">Oracle (OCI) driver for PDO </td><td class="v">Wez Furlong </td></tr>
<tr><td class="e">pcntl </td><td class="v">Jason Greene, Arnaud Le Blanc </td></tr>
<tr><td class="e">Perl Compatible Regexps </td><td class="v">Andrei Zmievski </td></tr>
<tr><td class="e">PHP Archive </td><td class="v">Gregory Beaver, Marcus Boerger </td></tr>
<tr><td class="e">PHP Data Objects </td><td class="v">Wez Furlong, Marcus Boerger, Sterling Hughes, George Schlossnagle, Ilia Alshanetsky </td></tr>
<tr><td class="e">PHP hash </td><td class="v">Sara Golemon, Rasmus Lerdorf, Stefan Esser, Michael Wallner, Scott MacVicar </td></tr>
<tr><td class="e">Posix </td><td class="v">Kristian Koehntopp </td></tr>
<tr><td class="e">PostgreSQL driver for PDO </td><td class="v">Edin Kadribasic, Ilia Alshanetsky </td></tr>
<tr><td class="e">PostgreSQL </td><td class="v">Jouni Ahto, Zeev Suraski, Yasuo Ohgaki, Chris Kings-Lynne </td></tr>
<tr><td class="e">Pspell </td><td class="v">Vlad Krupin </td></tr>
<tr><td class="e">Readline </td><td class="v">Thies C. Arntzen </td></tr>
<tr><td class="e">Reflection </td><td class="v">Marcus Boerger, Timm Friebe, George Schlossnagle, Andrei Zmievski, Johannes Schlueter </td></tr>
<tr><td class="e">Sessions </td><td class="v">Sascha Schumann, Andrei Zmievski </td></tr>
<tr><td class="e">Shared Memory Operations </td><td class="v">Slava Poliakov, Ilia Alshanetsky </td></tr>
<tr><td class="e">SimpleXML </td><td class="v">Sterling Hughes, Marcus Boerger, Rob Richards </td></tr>
<tr><td class="e">SNMP </td><td class="v">Rasmus Lerdorf, Harrie Hazewinkel, Mike Jackson, Steven Lawrance, Johann Hanne, Boris Lytochkin </td></tr>
<tr><td class="e">SOAP </td><td class="v">Brad Lafountain, Shane Caraveo, Dmitry Stogov </td></tr>
<tr><td class="e">Sockets </td><td class="v">Chris Vandomelen, Sterling Hughes, Daniel Beulshausen, Jason Greene </td></tr>
<tr><td class="e">Sodium </td><td class="v">Frank Denis </td></tr>
<tr><td class="e">SPL </td><td class="v">Marcus Boerger, Etienne Kneuss </td></tr>
<tr><td class="e">SQLite 3.x driver for PDO </td><td class="v">Wez Furlong </td></tr>
<tr><td class="e">SQLite3 </td><td class="v">Scott MacVicar, Ilia Alshanetsky, Brad Dewar </td></tr>
<tr><td class="e">System V Message based IPC </td><td class="v">Wez Furlong </td></tr>
<tr><td class="e">System V Semaphores </td><td class="v">Tom May </td></tr>
<tr><td class="e">System V Shared Memory </td><td class="v">Christian Cartus </td></tr>
<tr><td class="e">tidy </td><td class="v">John Coggeshall, Ilia Alshanetsky </td></tr>
<tr><td class="e">tokenizer </td><td class="v">Andrei Zmievski, Johannes Schlueter </td></tr>
<tr><td class="e">XML </td><td class="v">Stig Bakken, Thies C. Arntzen, Sterling Hughes </td></tr>
<tr><td class="e">XMLReader </td><td class="v">Rob Richards </td></tr>
<tr><td class="e">xmlrpc </td><td class="v">Dan Libby </td></tr>
<tr><td class="e">XMLWriter </td><td class="v">Rob Richards, Pierre-Alain Joye </td></tr>
<tr><td class="e">XSL </td><td class="v">Christian Stocker, Rob Richards </td></tr>
<tr><td class="e">Zip </td><td class="v">Pierre-Alain Joye, Remi Collet </td></tr>
<tr><td class="e">Zlib </td><td class="v">Rasmus Lerdorf, Stefan Roehrich, Zeev Suraski, Jade Nicoletti, Michael Wallner </td></tr>
</tbody></table>
<table>
<tbody><tr class="h"><th colspan="2">PHP Documentation</th></tr>
<tr><td class="e">Authors </td><td class="v">Mehdi Achour, Friedhelm Betz, Antony Dovgal, Nuno Lopes, Hannes Magnusson, Philip Olson, Georg Richter, Damien Seguy, Jakub Vrana, Adam Harvey </td></tr>
<tr><td class="e">Editor </td><td class="v">Peter Cowburn </td></tr>
<tr><td class="e">User Note Maintainers </td><td class="v">Daniel P. Brown, Thiago Henrique Pojda </td></tr>
<tr><td class="e">Other Contributors </td><td class="v">Previously active authors, editors and other contributors are listed in the manual. </td></tr>
</tbody></table>
<table>
<tbody><tr class="h"><th>PHP Quality Assurance Team</th></tr>
<tr><td class="e">Ilia Alshanetsky, Joerg Behrens, Antony Dovgal, Stefan Esser, Moriyoshi Koizumi, Magnus Maatta, Sebastian Nohn, Derick Rethans, Melvyn Sopacua, Pierre-Alain Joye, Dmitry Stogov, Felipe Pena, David Soria Parra, Stanislav Malyshev, Julien Pauli, Stephen Zarkos, Anatol Belski, Remi Collet, Ferenc Kovacs </td></tr>
</tbody></table>
<table>
<tbody><tr class="h"><th colspan="2">Websites and Infrastructure team</th></tr>
<tr><td class="e">PHP Websites Team </td><td class="v">Rasmus Lerdorf, Hannes Magnusson, Philip Olson, Lukas Kahwe Smith, Pierre-Alain Joye, Kalle Sommer Nielsen, Peter Cowburn, Adam Harvey, Ferenc Kovacs, Levi Morrison </td></tr>
<tr><td class="e">Event Maintainers </td><td class="v">Damien Seguy, Daniel P. Brown </td></tr>
<tr><td class="e">Network Infrastructure </td><td class="v">Daniel P. Brown </td></tr>
<tr><td class="e">Windows Infrastructure </td><td class="v">Alex Schoenmaker </td></tr>
</tbody></table>
<h2>PHP License</h2>
<table>
<tbody><tr class="v"><td>
<p>
This program is free software; you can redistribute it and/or modify it under the terms of the PHP License as published by the PHP Group and included in the distribution in the file:  LICENSE
</p>
<p>This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
</p>
<p>If you did not receive a copy of the PHP license, or have any questions about PHP licensing, please contact license@php.net.
</p>
</td></tr>
</tbody></table>
</div><style></style></body>
</html>