import{a as q,b as $}from"./QScrollObserver.a7b947df.js";import{_ as E,I as L,K as h,L as v,M as r,T as l,N as t,as as n,S as i,aK as S,w as g,P as m,b6 as V,at as b,au as y,aq as C,av as M,aw as x,ar as k,aL as D,aM as A,U as Q}from"./index.5c8aeb45.js";import{Q as I,a as R,b as _,c as T,e as N,d as B}from"./QScrollArea.f10f4adc.js";import{Q as O}from"./QResizeObserver.7f90d0fa.js";import{Q as z}from"./QPage.568bd31f.js";import{C as w}from"./ClosePopup.9e3a1a19.js";import{a as d}from"./axios.bf56c3c5.js";import{u as P}from"./userinfo.6ef15d1c.js";import{s as F}from"./sha256.6c01c987.js";const u=P(),H="production",c=H.toLowerCase()=="development"?"http://localhost:3000":"",j=L({name:"UserManagement",data(){return{parallaxHeight:0,addEditUserDlgShow:!1,delUserDlgShow:!1,isModifyMode:!1,userColumns:[{name:"email",label:"Email",required:!0,field:"EMAIL",align:"left",sortable:!0},{name:"comment",label:"Comments",field:"COMMENT",align:"left",sortable:!1},{name:"role",label:"Role",field:"ROLE",sortable:!0}],usersList:[],selectedUsers:[],newUserMail:"",oldUserMail:"",newUserComment:"",newUserRole:{},newUserRoles:[{label:"Ultimate Administrator (0)",value:0,description:"This account has the all the permissions that a token can do."},{label:"Administrator (1)",value:1,description:"This account can modify all links created by administrators and normal users."},{label:"Normal User (99)",value:99,description:"This account can create links, and remove the links create by himself or herself."}]}},computed:{},async mounted(){try{let e=await d.get(c+"/acheck/profile",{withCredentials:!0});e.status==200&&e.data.status=="success"&&(u.isLoggedIn=!0,u.name=e.data.profile.name?e.data.profile.name:"",u.username=e.data.profile.username?e.data.profile.username:"");let s=await d.get(c+"/acheck/checkuser",{withCredentials:!0});if(s.status==200&&s.data.status=="success"){u.role=s.data.results[0].ROLE;let o=F.exports.sha256(u.username);u.avatarImgSource=`https://gravatar.com/avatar/${o}?s=256&d=retro`,await this.refreshUserList(),s.data.results[0].ROLE!=0}}catch(e){e.response&&(e.response.status==404?this.$router.push("/nopermission"):(u.isLoggedIn=!1,this.$q.notify({message:`${e.response.data.reason}`,color:"negative"}),this.$router.push("/login")))}},methods:{foregroundDivChanged(e){this.foregroundSize=e,this.parallaxHeight=(this.foregroundSize.height?this.foregroundSize.height:0)+96},formatTime(e){const s=(f,U=2)=>`${new Array(U).fill(0)}${f}`.slice(-U),o=new Date(e);return`${s(o.getFullYear(),4)}-${s(o.getMonth()+1)}-${s(o.getDate())} ${s(o.getHours())}:${s(o.getMinutes())}:${s(o.getSeconds())}`},addUserBtnClick(e){this.addEditUserDlgShow=!0,this.isModifyMode=!1,this.newUserMail="",this.newUserComment="",this.newUserRole=this.newUserRoles[this.newUserRoles.length-1]},editBtnClick(e){e&&(console.log(),this.addEditUserDlgShow=!0,this.isModifyMode=!0,this.newUserMail=e.EMAIL!=null?e.EMAIL:"",this.oldUserMail=this.newUserMail,this.newUserComment=e.COMMENT!=null?e.COMMENT:"",this.newUserRole=this.newUserRoles.find(s=>s.value==(e.ROLE!=null?e.ROLE:99)))},async submitAddUserDlg(e){if(e)try{if(this.$refs.userMailTextField.validate()){if(this.isModifyMode){if(this.oldUserMail!==this.newUserMail&&!await this.userTargetAvaliable(this.newUserMail)){this.$q.notify({message:"Target email used",color:"negative"});return}let o=await d.get(c+"/api/userremoveuser",{withCredentials:!0,params:{email:this.oldUserMail}});if(!(o.status==200&&o.data.status=="success")){this.$q.notify({message:`${o.data.reason}`,color:"negative"}),await this.refreshUserList();return}}let s=await d.get(c+"/api/useradduser",{withCredentials:!0,params:{email:this.newUserMail,comment:this.newUserComment==""?void 0:this.newUserComment,role:this.newUserRole.value}});s.status==200&&s.data.status=="success"&&(this.addEditUserDlgShow=!1,this.$q.notify({message:"Done",color:"positive"}),await this.refreshUserList())}}catch(s){console.error(s),s.response&&this.$q.notify({message:`${s.response.data.reason}`,color:"negative"}),await this.refreshUserList()}},async refreshUserList(){try{let e=await d.get(c+"/api/usergetuserlist",{withCredentials:!0});e.status==200&&e.data.status=="success"&&(this.usersList=e.data.results)}catch(e){console.error(e),e.response&&e.response.status!=403&&this.$q.notify({message:`${e.response.data.reason}`,color:"negative"})}},async submitRemoveUserDlg(e){try{let s=[];for(const f of this.selectedUsers)s.push(f.EMAIL);let o=await d.post(c+"/api/userbatchremoveuser",{emails:s},{withCredentials:!0});o.status==200&&o.data.status=="success"&&(this.$q.notify({message:"Done",color:"positive"}),this.refreshUserList(),this.selectedUsers=[],this.delUserDlgShow=!1)}catch(s){console.error(s),s.response&&this.$q.notify({message:`${s.response.data.reason}`,color:"negative"})}},async userTargetAvaliable(e){try{let s=await d.get(c+"/api/usergetuser",{withCredentials:!0,params:{email:e}});if(s.status==200&&s.data.status=="success")return!1;throw ReferenceError("Internal Server Error 0ccurred.")}catch(s){if(console.error(s),s.response&&s.response.status==404)return!0;throw ReferenceError("Internal Server Error Occurred.")}}}}),K={class:"column q-py-lg q-mt-none q-gutter-y-md flex items-center full-width content-center"},Y={class:"full-width",ref:"foregrounddiv"},W=l("div",{class:"full-width"},[l("p",{style:{"text-shadow":"2px 2px #4c3d30"},class:"gt-xs text-center text-h3 text-white"},"User Manager ")],-1),G=l("div",{class:"full-width"},[l("p",{style:{"text-shadow":"2px 2px #4c3d30"},class:"gt-xs text-center text-h6 text-white"},"Add or remove users")],-1),J=l("div",{class:"full-width"},[l("p",{style:{"text-shadow":"2px 2px #4c3d30"},class:"xs text-center text-h5 text-white"},"User Manager")],-1),X=l("div",{class:"full-width"},[l("p",{style:{"text-shadow":"2px 2px #4c3d30"},class:"xs text-center text-body2 text-white"},"Add or remove users")],-1),Z=l("div",{class:"full-width row justify-center q-pt-md"},[l("div",{class:"col-10 gt-xs"})],-1),ee={class:"row full-width justify-center"},se={class:"col-11 col-md-8"},te={class:"flex column"},le={class:"flex row no-wrap justify-start items-center"},ae=l("div",{class:"text-h6"},"Approved accounts",-1),re=l("div",{class:"text-body2 q-pt-sm"},"Microsoft accounts that have permissions to create, modify or delete short links. If no account listed, only the super token has the permissions to operate the links.",-1),oe=l("div",{class:"text-body2 q-pt-sm"},"Please remind that you cannot promote or demote yourself.",-1),ie={class:"content-start flex full-width"},ne={class:"content-start flex no-wrap"},de=l("div",{class:"q-pt-none q-pb-xl"},null,-1),ue=l("div",{class:"text-h6"},"Add a user",-1),ce=l("div",{class:"text-h6"},"Warning",-1),me={class:"q-my-none"},he=l("div",{class:"fixed-bottom-right text-white q-pb-sm q-pr-md"},[l("p",{class:"attribution q-ma-none text-caption",style:{"white-space":"nowrap"}},[m('"'),l("a",{rel:"noopener noreferrer",class:"text-white",href:"https://www.flickr.com/photos/69806124@N04/6775983965"},"Keyboard"),m('" by '),l("a",{rel:"noopener noreferrer",class:"text-white",href:"https://www.flickr.com/photos/69806124@N04"},"LawlessTech"),m(" is licensed under "),l("a",{rel:"noopener noreferrer",class:"text-white",href:"https://creativecommons.org/licenses/by/2.0/?ref=openverse"},[m("CC BY 2.0 "),l("img",{src:"https://mirrors.creativecommons.org/presskit/icons/cc.svg",style:{height:"0.75em","margin-right":"0.125em",display:"inline"}}),l("img",{src:"https://mirrors.creativecommons.org/presskit/icons/by.svg",style:{height:"0.75em","margin-right":"0.125em",display:"inline"}})])])],-1);function fe(e,s,o,f,U,pe){return h(),v(z,{class:"flex column flex-center q-px-none q-px-md-none bg-image"},{default:r(()=>[l("div",K,[l("div",Y,[W,G,J,X,Z,l("div",ee,[l("div",se,[t(y,{class:"my-card",style:{"background-color":"rgba(250,250,250,.8)"}},{default:r(()=>[t(n,null,{default:r(()=>[l("div",te,[l("div",le,[ae,t(q),t(i,{flat:"",rounded:"",class:S(["q-ml-xs gt-sm",{invisible:e.selectedUsers.length==0}]),color:"primary",icon:"mdi-account-minus",label:"Remove selected",disable:e.selectedUsers.length==0,onClick:s[0]||(s[0]=a=>e.delUserDlgShow=!0)},null,8,["disable","class"]),t(i,{flat:"",rounded:"",class:"q-ml-xs gt-sm",color:"primary",icon:"mdi-account-plus",label:"Add account",onClick:e.addUserBtnClick},null,8,["onClick"]),t(i,{flat:"",round:"",class:"q-ml-xs lt-md",color:"primary",icon:"mdi-dots-vertical"},{default:r(()=>[t($,null,{default:r(()=>[t(I,{style:{"min-width":"100px"}},{default:r(()=>[g((h(),v(R,{clickable:"",onClick:e.addUserBtnClick},{default:r(()=>[t(_,null,{default:r(()=>[m("Add account")]),_:1})]),_:1},8,["onClick"])),[[w]]),g((h(),v(R,{clickable:"",disable:e.selectedUsers.length==0,onClick:s[1]||(s[1]=a=>e.delUserDlgShow=!0)},{default:r(()=>[t(_,null,{default:r(()=>[m("Remove selected")]),_:1})]),_:1},8,["disable"])),[[w]])]),_:1})]),_:1})]),_:1})]),re,oe])]),_:1}),t(V,{inset:""}),t(n,{class:"q-mx-sm"},{default:r(()=>[t(T,{flat:"",rows:e.usersList,columns:e.userColumns,"row-key":"EMAIL","no-data-label":"No user",selection:"multiple",selected:e.selectedUsers,"onUpdate:selected":s[2]||(s[2]=a=>e.selectedUsers=a),class:"transparent"},{"header-selection":r(a=>[l("div",ie,[t(b,{modelValue:a.selected,"onUpdate:modelValue":p=>a.selected=p},null,8,["modelValue","onUpdate:modelValue"])])]),"body-selection":r(a=>[l("div",ne,[t(b,{modelValue:a.selected,"onUpdate:modelValue":p=>a.selected=p},null,8,["modelValue","onUpdate:modelValue"]),t(i,{flat:"",round:"",color:"primary",icon:"mdi-pencil",class:"q-ml-xs",onClick:p=>e.editBtnClick(a.row)},null,8,["onClick"])])]),_:1},8,["rows","columns","selected"])]),_:1})]),_:1})])]),de,t(O,{onResize:e.foregroundDivChanged},null,8,["onResize"])],512)]),t(x,{modelValue:e.addEditUserDlgShow,"onUpdate:modelValue":s[6]||(s[6]=a=>e.addEditUserDlgShow=a),persistent:""},{default:r(()=>[t(y,{style:{width:"450px"}},{default:r(()=>[t(n,null,{default:r(()=>[ue]),_:1}),t(n,{class:"q-pt-none"},{default:r(()=>[t(C,{modelValue:e.newUserMail,"onUpdate:modelValue":s[3]||(s[3]=a=>e.newUserMail=a),label:"Email",rules:[a=>!!a||"Field Required"],ref:"userMailTextField"},null,8,["modelValue","rules"]),t(C,{modelValue:e.newUserComment,"onUpdate:modelValue":s[4]||(s[4]=a=>e.newUserComment=a),label:"Comment",hint:" "},null,8,["modelValue"]),t(N,{modelValue:e.newUserRole,"onUpdate:modelValue":s[5]||(s[5]=a=>e.newUserRole=a),label:"Role",options:e.newUserRoles,hint:e.newUserRole?e.newUserRole.description:""},null,8,["modelValue","options","hint"])]),_:1}),t(M,{align:"right",class:"text-primary"},{default:r(()=>[g(t(i,{flat:"",label:"Cancel"},null,512),[[w]]),t(i,{flat:"",label:e.isModifyMode?"Modify":"Add",onClick:e.submitAddUserDlg},null,8,["label","onClick"])]),_:1})]),_:1})]),_:1},8,["modelValue"]),t(x,{modelValue:e.delUserDlgShow,"onUpdate:modelValue":s[7]||(s[7]=a=>e.delUserDlgShow=a),persistent:""},{default:r(()=>[t(y,{style:{"min-width":"350px","max-width":"450px"}},{default:r(()=>[t(n,null,{default:r(()=>[ce]),_:1}),t(n,{class:"q-pt-none"},{default:r(()=>[m(" Are you sure to remove the users below? There will be no way to restore! ")]),_:1}),t(n,{class:"q-pt-none"},{default:r(()=>[t(B,{"thumb-style":e.thumbStyle,"bar-style":e.barStyle,style:{height:"100px"}},{default:r(()=>[l("ul",me,[(h(!0),k(A,null,D(e.selectedUsers,a=>(h(),k("li",{key:a},Q(a.EMAIL),1))),128))])]),_:1},8,["thumb-style","bar-style"])]),_:1}),t(M,{align:"right",class:"text-primary"},{default:r(()=>[g(t(i,{flat:"",label:"No"},null,512),[[w]]),t(i,{flat:"",label:"Yes",onClick:e.submitRemoveUserDlg},null,8,["onClick"])]),_:1})]),_:1})]),_:1},8,["modelValue"]),he]),_:1})}var ke=E(j,[["render",fe]]);export{ke as default};