function yzq_p(c){var w=window;if(w.yzq_d==null)w.yzq_d=new Object();w.yzq_d['p']=c;}
function yzq1(u){var d=document;if(d.yzq0==null){d.yzq0=new Array();d.yzq0.c=0;}var b=d.yzq0;b[++b.c]=new Image();b[b.c].src=u;}
function yzq_sr(){var w=window;var d=w.yzq_d;if(d==null)return;var u=yzq2+d.p;if(u.length > yzq3){w.yzq_d=null;return;}d.p=null;var z="";var s=0;var o=Math.random();var hp=(d.hasOwnProperty!=null);var b;for(b in d){if(typeof d[b]=='string'){if(hp&&!d.hasOwnProperty(b))continue;if(u.length+z.length+d[b].length<=yzq3)z+=d[b];else {if(u.length+d[b].length > yzq3){}else {s++;yzq1(u+z+"&Q="+s+"&O="+o);z=d[b];}}}}if(s)s++;yzq1(u+z+"&Q="+s+"&O="+o);w.yzq_d=null;}
function yzq4(e){yzq_sr();}
function yzq5(e){yzq_sr();}
function yzq6(yzq7,yzq8,yzq9){if(yzq9){var o=yzq9.toString();var m=yzq7;var a=o.match(new RegExp("\\(([^\\)]*)\\)"));a=(a[1].length >0?a[1]:"e");m=m.replace(new RegExp("\\([^\\)]*\\)","g"),"("+a+")");if(o.indexOf(m)<0){var b=o.indexOf("{");if(b > 0)o=o.substring(b,o.length);else return yzq9;o=o.replace(new RegExp("([^a-zA-Z0-9$_])this([^a-zA-Z0-9$_])","g"),"$1yzq_this$2");var s=m+";"+"var rv = f( "+a+",this);";var n="{"+"var a0 = '"+a+"';"+"var ofb = '"+escape(o)+"' ;"+"var f = new Function( a0, 'yzq_this', unescape(ofb));"+s+"return rv;"+"}";return new Function(a,n);}else return yzq9;}return yzq8;}
function yzq_eh(){if(yzq10){yzq_sr();return;}if(yzq11||yzq12){this.onload=yzq6("yzq_onload(e)",yzq4,this.onload,0);if(yzq11&&typeof(this.onbeforeunload)!=yzq13)this.onbeforeunload=yzq6("yzq_dobeforeunload(e)",yzq5,this.onbeforeunload,0);}}
function yzq_s(){setTimeout("yzq_sr()",1);}
var yzq2='//us.bc.yahoo.com/b?';var yzq14=navigator.appName;var yzq15=navigator.appVersion;var yzq16=navigator.userAgent;var yzq17=parseInt(yzq15);var yzq18=yzq14.indexOf("Microsoft");var yzq11=yzq18!=-1&&yzq17>=4;var yzq12=(yzq14.indexOf("Netscape")!=-1||yzq14.indexOf("Opera")!=-1)&&yzq17>=4;var yzq13="undefined";var yzq22="object";var yzq3=2000;
