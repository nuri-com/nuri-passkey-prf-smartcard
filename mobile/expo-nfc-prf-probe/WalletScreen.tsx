import { useRef, useState } from 'react';
import { ScrollView, View, Text, TextInput, Pressable, StyleSheet } from 'react-native';
import Svg, { G, Path, Rect } from 'react-native-svg';
import * as Clipboard from 'expo-clipboard';
import NuriLogo, { NURI_LOGO_PATH } from './NuriLogo';
import { cardInfoUrl, displayUsername, displayBalance } from './src/cardIdentity';
import { createSoftwareWallet, registerSoftwareWallet, receiveWallet, openWallet, type ArkadeReceiveWallet, type ArkadeWalletSnapshot } from './src/arkadeWallet';
import { withPinCard, signCardDemo, type CardSigner } from './src/musig2CardPin';
import { preflightSend, proveSigner } from './src/arkadePreflight';
const C={bg:'#fdf6e3',text:'#657b83',heading:'#586e75',accent:'#268bd2',success:'#2aa198',error:'#dc322f'};
export function WalletScreen(){
 const [screen,setScreen]=useState('home'),[wallet,setWallet]=useState<ArkadeReceiveWallet|null>(null),[full,setFull]=useState<ArkadeWalletSnapshot|null>(null),[busy,setBusy]=useState(false),[error,setError]=useState(''),[name,setName]=useState(''),[software,setSoftware]=useState(false),[pin,setPin]=useState(''),[destination,setDestination]=useState(''),[amount,setAmount]=useState('330'),[bitcoin,setBitcoin]=useState(false),[success,setSuccess]=useState('');
 const signer=useRef<CardSigner|null>(null),locked=useRef(false);
 const log=(s:string)=>console.info('[NuriWallet]',s);
 async function run(fn:(s:CardSigner)=>Promise<void>, signing=false){if(locked.current)return;locked.current=true;setBusy(true);setError('');setSuccess('');const p=pin;setPin('');try{if(software){if(!signer.current)signer.current=await createSoftwareWallet();await fn(signer.current);}else await withPinCard(signing?p:'',()=>{},fn);}catch(e){log(e instanceof Error?e.message:String(e));setError(e instanceof Error&&e.message.toLowerCase().includes('insufficient')?'Insufficient funds':'Please try again');}finally{locked.current=false;setBusy(false);}}
 async function load(s:CardSigner){
  const key=await s.pubkey();
  if(software){await registerSoftwareWallet(key);log('Software registration verified');}
  const receive=await receiveWallet(key);setWallet(receive);
  log('Receive '+JSON.stringify({ark:receive.arkAddress,boarding:receive.boardingAddress,key:receive.clientPubkey}));
  // A name lookup must never prevent reading the real card's balance.
  setName('');
  try {
   const response=await fetch(cardInfoUrl(receive.clientPubkey));
   if(response.ok){const info=await response.json();setName(displayUsername(info.username||info.lnurl?.username||info.recovery?.username));}
  } catch { log('Name lookup unavailable'); }
  const snapshot=await openWallet(key);setFull(snapshot);log('Balance '+snapshot.balance);
 }
 const button=(label:string,action:()=>void,variant:'primary'|'secondary'|'text'='primary')=> <Pressable accessibilityRole="button" accessibilityLabel={label} disabled={busy} onPress={action} style={({pressed})=>[styles.button,variant==='primary'?styles.primary:variant==='secondary'?styles.secondary:styles.textButton,pressed&&styles.pressed]}><Text style={[styles.buttonLabel,variant==='primary'?styles.primaryLabel:styles.secondaryLabel]}>{label}</Text></Pressable>;
 const input=(label:string,value:string,set:(v:string)=>void,secure=false)=><TextInput accessibilityLabel={label} placeholder={label} placeholderTextColor={C.text} value={value} onChangeText={set} secureTextEntry={secure} autoCapitalize="none" style={styles.input}/>;
 return <ScrollView style={styles.root} contentContainerStyle={[styles.content,(busy||(screen==='home'&&!full))&&styles.centered]} keyboardShouldPersistTaps="handled">
 {busy?<View style={styles.scan}><CardIllustration/><Text style={styles.scanText}>Hold your Nuri card to the phone</Text></View>:<>
 {screen==='home'&&<>{full?<>
  <View style={styles.identity}><NuriLogo/>{name?<Text style={styles.text}>{name}</Text>:null}</View>
  <Pressable accessibilityRole="button" accessibilityLabel="Balance" onPress={()=>void run(load)} onLongPress={()=>{setScreen('demo');setSuccess('');}} style={styles.balance}><Text style={styles.heading}>{displayBalance(full.homeBalance)}</Text></Pressable>
  <View style={styles.actions}>{button('Receive',()=>{setScreen('receive');setError('');})}{button('Send',()=>{setScreen('send');setError('');},'secondary')}</View>
 </>:<>
  <Pressable accessibilityLabel="Nuri card" onLongPress={()=>{setScreen('demo');setSuccess('');}}><CardIllustration/></Pressable>
  {button('Scan card',()=>void run(load))}
 </>}</>}
 {screen==='receive'&&<><Text style={styles.heading}>Receive</Text>{wallet&&<><Text selectable style={styles.text}>{bitcoin?wallet.boardingAddress:wallet.arkAddress}</Text>{button('Copy',()=>{void Clipboard.setStringAsync(bitcoin?wallet.boardingAddress:wallet.arkAddress);setSuccess('Copied');})}{button(bitcoin?'Ark':'Bitcoin',()=>setBitcoin(!bitcoin),'secondary')}</>}</>}
 {screen==='send'&&<><Text style={styles.heading}>Send</Text>{input('Address',destination,setDestination)}{input('Sats',amount,setAmount)}{button('Send',()=>void run(async s=>{if(!full)throw Error('Balance unavailable');await preflightSend(full,destination,Number(amount),s,log);},true))}</>}
 {screen==='demo'&&<><Text style={styles.heading}>Sign</Text>{!software&&input('PIN',pin,setPin,true)}{button('Sign',()=>{if(software){void run(async s=>{await proveSigner(s);setSuccess('Signature valid');});return;}const p=pin;setPin('');setBusy(true);void signCardDemo('Nuri card demo',p,()=>{}).then(r=>setSuccess(r.verified?'Signature valid':'Please try again')).catch(()=>setError('Please try again')).finally(()=>setBusy(false));})}{button(software?'Use real card':'Use software card',()=>{setSoftware(!software);setWallet(null);setFull(null);setName('');setScreen('home');setError('');},'secondary')}</>}
 {screen!=='home'&&button('Back',()=>{setScreen('home');setError('');setSuccess('');},'text')}
 </>}{error?<Text style={[styles.text,{color:C.error}]}>{error}</Text>:null}{success?<Text style={[styles.text,{color:C.success}]}>{success}</Text>:null}
 </ScrollView>;
}
function CardIllustration(){
 return <Svg width="100%" height={190} viewBox="0 0 342.4 216" accessible={false}>
  <Rect x={1} y={1} width={340.4} height={214} rx={18} fill="#eee8d5" stroke="#93a1a1" strokeWidth={1.5}/>
  <G transform="translate(28 28) scale(1.5)"><Path d={NURI_LOGO_PATH} fill={C.heading}/></G>
  <G fill="none" stroke={C.heading} strokeWidth={3} strokeLinecap="round">
   <Path d="M274 91 Q283 108 274 125"/><Path d="M286 83 Q300 108 286 133"/><Path d="M298 75 Q317 108 298 141"/>
  </G>
 </Svg>;
}
const styles=StyleSheet.create({
 root:{flex:1,backgroundColor:C.bg},
 content:{flexGrow:1,padding:28,gap:28,paddingTop:70,paddingBottom:40},
 centered:{justifyContent:'center'},
 identity:{alignItems:'center',gap:24},
 balance:{alignItems:'center',paddingVertical:20},
 actions:{gap:16,marginTop:12},
 scan:{alignItems:'center',gap:32,width:'100%'},
 scanText:{fontSize:17,lineHeight:26,color:C.text,textAlign:'center'},
 text:{fontSize:17,lineHeight:26,color:C.text},
 heading:{fontSize:28,lineHeight:36,color:C.heading},
 button:{width:'100%',minHeight:56,borderRadius:14,padding:18,alignItems:'center',justifyContent:'center'},
 primary:{backgroundColor:C.accent},
 secondary:{borderWidth:1.5,borderColor:'#93a1a1'},
 textButton:{backgroundColor:'transparent'},
 buttonLabel:{fontSize:17,lineHeight:22},
 primaryLabel:{color:C.bg},
 secondaryLabel:{color:C.heading},
 pressed:{opacity:0.72},
 input:{fontSize:17,color:C.text,paddingVertical:16,borderBottomWidth:1,borderBottomColor:C.text}
});
