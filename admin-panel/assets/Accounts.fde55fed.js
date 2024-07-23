import{Q as b,a as r,b as y,c as d,d as c}from"./QPage.fe4daae0.js";import{Q as C,a as v,b as k,c as f,d as p,e as L,C as w}from"./ClosePopup.543ce8a7.js";import{_ as R,E as D,G as u,H as S,I as l,J as s,L as m,M as o,w as g,X as i,Y as U,Z as V,$ as q,a0 as A}from"./index.c3cb6c00.js";import{a as n}from"./axios.bf56c3c5.js";import{a as $}from"./login-state.cb3efe2c.js";import"./QScrollObserver.a61333c8.js";const M=D({name:"AccountsPage",data(){return{userColumns:[{name:"email",label:"Email",required:!0,field:"EMAIL",align:"left",sortable:!0},{name:"comment",label:"Comments",field:"COMMENT",align:"left",sortable:!1},{name:"role",label:"Role",field:"ROLE",sortable:!0}],usersList:[],emptyUserList:[],selectedUsers:[],adduserDlgShow:!1,deluserDlgShow:!1,newUserMail:"",newUserComment:"",newUserRole:{},newUserRoles:[{label:"Ultimate Administrator (0)",value:0,description:"This account has the all the permissions that a token can do."},{label:"Administrator (1)",value:1,description:"This account can modify all links created by administrators and normal users."},{label:"Normal User (99)",value:99,description:"This account can create links, and remove the links create by himself or herself."}]}},methods:{addUserBtnClick(){this.adduserDlgShow=!0,this.newUserMail="",this.newUserComment="",this.newUserRole=this.newUserRoles[this.newUserRoles.length-1]},async submitAddUserDlg(){if(await this.$refs.userMailTextField.validate())try{let e=await n.get("/api/adduser",{withCredentials:!0,params:{email:this.newUserMail,comment:this.newUserComment,role:this.newUserRole.value}});e.status==200&&e.data.status=="success"&&this.$q.notify({message:"Done",color:"positive"}),await this.refreshUserLists(),this.adduserDlgShow=!1}catch(e){e.response&&this.$q.notify({message:`${e.response.data.reason}`,color:"negative"}),console.error(e)}},async submitRemoveUserDlg(){try{let e=[];for(const h of this.selectedUsers)e.push(h.EMAIL);this.selectedUsers=[];let t=await n.post("/api/batchremoveuser",{users:e},{withCredentials:!0});t.status==200&&t.data.status=="success"&&(this.$q.notify({message:"Done",color:"positive"}),this.deluserDlgShow=!1)}catch(e){e.response&&this.$q.notify({message:`${e.response.data.reason}`,color:"negative"}),console.error(e)}await this.refreshUserLists()},async refreshUserLists(){try{this.usersList=[];let e=await n.get("/api/getuserlist",{withCredentials:!0});e.status==200&&e.data.status=="success"&&(this.usersList=e.data.results)}catch(e){e.response&&this.$q.notify({message:`${e.response.data.reason}`,color:"negative"}),console.error(e)}}},async mounted(){const e=$();try{let t=await n.get("/api/getme",{withCredentials:!0});t.status!=200||t.data.user!="root"?e.isLogin=!1:e.isLogin=!0}catch{e.isLogin=!1}e.isLogin?await this.refreshUserLists():this.$router.push("/")}}),Q=i("div",{class:"text-h6"},"Approved accounts",-1),E=i("br",null,null,-1),T=i("div",{class:"text-h6"},"Add a user",-1),B=i("div",{class:"text-h6"},"Warning",-1),I={class:"q-my-none"};function N(e,t,h,F,P,G){return u(),S(b,{class:"flex column items-start content-center q-gutter-y-md q-pt-md q-px-lg q-px-md-none"},{default:l(()=>[s(d,{bordered:"",class:"my-card full-width",style:{"max-width":"800px"}},{default:l(()=>[s(r,null,{default:l(()=>[Q]),_:1}),s(r,{class:"q-pt-none"},{default:l(()=>[m(" Microsoft accounts that have permissions to create, modify or delete short links. "),E,m(" If no account listed, only the super token has the permissions to operate the links. ")]),_:1}),s(C,{inset:""}),s(r,{class:"q-mx-sm"},{default:l(()=>[s(v,{flat:"",bordered:"",rows:e.usersList,columns:e.userColumns,"row-key":"EMAIL","no-data-label":"No user",selection:"multiple",selected:e.selectedUsers,"onUpdate:selected":t[0]||(t[0]=a=>e.selectedUsers=a)},null,8,["rows","columns","selected"])]),_:1}),s(r,{class:"flex row justify-end items-center"},{default:l(()=>[s(y,{push:"",flat:""},{default:l(()=>[s(o,{label:"Add",icon:"mdi-account-plus",onClick:e.addUserBtnClick},null,8,["onClick"]),s(o,{label:"Remove",icon:"mdi-account-minus",disable:e.selectedUsers.length==0,onClick:t[1]||(t[1]=a=>e.deluserDlgShow=!0)},null,8,["disable"])]),_:1})]),_:1})]),_:1}),s(p,{modelValue:e.adduserDlgShow,"onUpdate:modelValue":t[5]||(t[5]=a=>e.adduserDlgShow=a),persistent:""},{default:l(()=>[s(d,{style:{width:"450px"}},{default:l(()=>[s(r,null,{default:l(()=>[T]),_:1}),s(r,{class:"q-pt-none"},{default:l(()=>[s(c,{modelValue:e.newUserMail,"onUpdate:modelValue":t[2]||(t[2]=a=>e.newUserMail=a),label:"Email",rules:[a=>!!a||"Field Required"],ref:"userMailTextField"},null,8,["modelValue","rules"]),s(c,{modelValue:e.newUserComment,"onUpdate:modelValue":t[3]||(t[3]=a=>e.newUserComment=a),label:"Comment",hint:" "},null,8,["modelValue"]),s(k,{modelValue:e.newUserRole,"onUpdate:modelValue":t[4]||(t[4]=a=>e.newUserRole=a),label:"Role",options:e.newUserRoles,hint:e.newUserRole?e.newUserRole.description:""},null,8,["modelValue","options","hint"])]),_:1}),s(f,{align:"right",class:"text-primary"},{default:l(()=>[g(s(o,{flat:"",label:"Cancel"},null,512),[[w]]),s(o,{flat:"",label:"Add User",onClick:e.submitAddUserDlg},null,8,["onClick"])]),_:1})]),_:1})]),_:1},8,["modelValue"]),s(p,{modelValue:e.deluserDlgShow,"onUpdate:modelValue":t[6]||(t[6]=a=>e.deluserDlgShow=a),persistent:""},{default:l(()=>[s(d,{style:{"min-width":"350px","max-width":"450px"}},{default:l(()=>[s(r,null,{default:l(()=>[B]),_:1}),s(r,{class:"q-pt-none"},{default:l(()=>[m(" Are you sure to remove the users below? There will be no way to restore! ")]),_:1}),s(r,{class:"q-pt-none"},{default:l(()=>[s(L,{"thumb-style":e.thumbStyle,"bar-style":e.barStyle,style:{height:"100px"}},{default:l(()=>[i("ul",I,[(u(!0),U(q,null,V(e.selectedUsers,a=>(u(),U("li",{key:a},A(a.EMAIL),1))),128))])]),_:1},8,["thumb-style","bar-style"])]),_:1}),s(f,{align:"right",class:"text-primary"},{default:l(()=>[g(s(o,{flat:"",label:"No"},null,512),[[w]]),s(o,{flat:"",label:"Yes",onClick:e.submitRemoveUserDlg},null,8,["onClick"])]),_:1})]),_:1})]),_:1},8,["modelValue"])]),_:1})}var X=R(M,[["render",N]]);export{X as default};