sj_evt.bind("onP1",function(){var t=sj_gx(),n=_ge("sw_tlm"),r=_ge("sw_tll"),u=!1,f=null,e=!1,h="login",c="onPopTR";if(n&&r){r.clearD=function(){n._m=!1,i(),u=!1,e=!1,f=null};var s=function(){var s,r;u||(u=!0,s=n.getAttribute("_iid"),s&&(r="/fd/fb/mulmfg?IG="+_G.IG+"&IID="+s+"&ru="+encodeURIComponent(location.href),_w.sb_tlmfn&&(r=r+"&CAH=1"),t.open("GET",r,!0),t.onreadystatechange=function(){t.readyState==4&&t.status==200&&t.responseText&&(n.innerHTML=t.responseText,e=!0,f&&o(f))},t.send(null)))},i=function(){n._m||(n.style.display="none",sj_ue(document,"click",i))},o=function(t){if(f=t,!u){s();return}if(e){r.style.outline="none";var o=n.style;o.display!="block"?(o.display="block",sj_evt.fire(c,h),sj_be(document,"click",i)):(o.display="none",sj_ue(document,"click",i)),sj_sp(t)}};sj_be(r,"mouseover",s),sj_be(r,"click",o),sj_evt.bind(c,function(n){n.length>1&&n[1]!=h&&i()})}},1,50)