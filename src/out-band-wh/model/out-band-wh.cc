#include "out-band-wh.h"

#include "ns3/log.h"
#include "ns3/inet-socket-address.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/mac48-address.h"

#include "ns3/ipv4-header.h"
#include "ns3/udp-header.h"

#include "ns3/aodv-packet.h"


#include "ns3/udp-l4-protocol.h"       // ★ 追加
#include "ns3/aodv-routing-protocol.h" // ★ 追加
#include "ns3/ipv4-address.h"
#include "ns3/uinteger.h"   // ★ UintegerValue, MakeUintegerAccessor, Checker
#include "ns3/enum.h"       // （任意）EnumAttributeにするなら
#include "ns3/boolean.h"    // （任意）
#include "ns3/buffer.h"
#include <iomanip>


namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("WormholeApp");

// ==============================
// WhTag 実装
// ==============================

NS_OBJECT_ENSURE_REGISTERED (WhTag);

TypeId
WhTag::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::WhTag")
    .SetParent<Tag> ()
    .SetGroupName ("Wormhole")
  ;
  return tid;
}

TypeId
WhTag::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}

// ======================================================
// ★追加：Hello(RREP形式) 判定ヘルパ
//   ns-3 AODVのHelloはRREPで hopCount=0, dst==origin==送信元, かつIP宛先がブロードキャスト…等の特徴
// ======================================================
static bool
IsHelloRrep (const aodv::RrepHeader& rrep, const Ipv4Header& ip)
{
  // const Ipv4Address ipSrc = ip.GetSource ();
  // const Ipv4Address ipDst = ip.GetDestination ();

  // Helloメッセージの場合、メッセージをドロップ
  if (rrep.GetDst () == rrep.GetOrigin ())
    {
      return true;
    }
  return false;
}

// ==============================
// WormholeApp 実装
// ==============================

NS_OBJECT_ENSURE_REGISTERED (WormholeApp);

TypeId
WormholeApp::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::WormholeAppOutBand")
    .SetParent<Application> ()
    .SetGroupName ("Wormhole")
    .AddConstructor<WormholeApp> ()

    // ★追加：シナリオから設定できる属性
    .AddAttribute ("ForwardMode",
                   "0: tunnel all IPv4 packets, 1: tunnel only RREQ/RREP (exclude Hello).",
                   UintegerValue (0),
                   MakeUintegerAccessor (&WormholeApp::m_forwardMode),
                   MakeUintegerChecker<int> (0, 1));
  return tid;
}

WormholeApp::WormholeApp ()
  : m_dev (0),
    m_socket (0),
    m_peer (),
    m_port (0),
    m_forwardMode (0)
{
}

WormholeApp::~WormholeApp ()
{
  m_dev = 0;
  m_socket = 0;
}

void
WormholeApp::Setup (Ptr<NetDevice> dev, Ipv4Address peer, uint16_t port)
{
  m_dev  = dev;
  m_peer = peer;
  m_port = port;
}

void
WormholeApp::StartApplication ()
{
  NS_LOG_FUNCTION (this);

  // UDP ソケット作成（WH トンネル）
  m_socket = Socket::CreateSocket (GetNode (), UdpSocketFactory::GetTypeId ());
  m_socket->Bind (InetSocketAddress (Ipv4Address::GetAny (), m_port));
  m_socket->SetRecvCallback (MakeCallback (&WormholeApp::TunnelRecv, this));

  // Promiscuous スニファ設定
  m_dev->SetPromiscReceiveCallback
    (MakeCallback (&WormholeApp::PromiscSniff, this));
}

void
WormholeApp::StopApplication ()
{
  NS_LOG_FUNCTION (this);

  if (m_socket)
    {
      m_socket->Close ();
      m_socket = 0;
    }
}

// --------------------------------------------------------
// PromiscSniff: 無線で受信したパケットをキャプチャしてトンネルへ
//   ただし「WH が再注入したパケット（WhTag 付き）」は無視する
// --------------------------------------------------------
bool
WormholeApp::PromiscSniff (Ptr<NetDevice> dev,
                           Ptr<const Packet> pkt,
                           uint16_t protocol,
                           const Address &src,
                           const Address &dst,
                           NetDevice::PacketType type)
{
  // ループ防止タグは除外
  WhTag tag;
  if (pkt->PeekPacketTag (tag))
    return true;

  // IPv4以外は無視
  if (protocol != 0x0800)
    return true;

  Ptr<Packet> copy = pkt->Copy ();

  // IP/UDP を確認
  Ipv4Header ip;
  if (!copy->PeekHeader (ip))
    return true;

  // ============================
  // ForwardMode=0: 全て転送
  // ============================
  if (m_forwardMode == 0)
  {
    Ptr<Packet> sendPkt = pkt->Copy ();

    Mac48Address srcMac = Mac48Address::ConvertFrom (src);
    Mac48Address dstMac = Mac48Address::ConvertFrom (dst);

    WhTunnelHeader meta;
    meta.Set(/*etherType=*/protocol,
              /*packetType=*/static_cast<uint8_t>(type),
              /*srcMac=*/srcMac,
              /*dstMac=*/dstMac,
              /*ipSrc=*/ip.GetSource (),
              /*ipDst=*/ip.GetDestination ());

    sendPkt->AddHeader (meta);

    if (m_socket)
      {
        m_socket->SendTo (sendPkt, 0, InetSocketAddress (m_peer, m_port));
      }
    return true;
  }

// ============================
// ForwardMode=1: RREQ/RREPのみ(Hello除外)
// ============================

// UDPでないなら対象外（RREQ/RREPはUDP）
if (ip.GetProtocol () != UdpL4Protocol::PROT_NUMBER)
  return true;

copy->RemoveHeader (ip);
UdpHeader udp;
if (!copy->PeekHeader (udp))
  return true;

// AODVポート以外は対象外
if (udp.GetDestinationPort () != aodv::RoutingProtocol::AODV_PORT &&
    udp.GetSourcePort      () != aodv::RoutingProtocol::AODV_PORT)
  return true;

// AODVタイプを見て RREQ/RREP のみに限定
copy->RemoveHeader (udp);

aodv::TypeHeader th;
if (!copy->RemoveHeader (th))
  return true;

bool allowTunnel = false;

if (th.Get () == aodv::AODVTYPE_RREQ)
{
  allowTunnel = true;
}
else if (th.Get () == aodv::AODVTYPE_RREP)
{
  aodv::RrepHeader rrep;
  if (!copy->RemoveHeader (rrep))
    return true;

  // ★Hello(RREP形式)は除外
  if (!IsHelloRrep (rrep, ip))
    {
      allowTunnel = true;
    }
}

if (!allowTunnel)
  return true;

// ---- ここまで来たらトンネル送信 ----
Ptr<Packet> sendPkt = pkt->Copy ();

Mac48Address srcMac = Mac48Address::ConvertFrom (src);
Mac48Address dstMac = Mac48Address::ConvertFrom (dst);

WhTunnelHeader meta;
meta.Set(/*etherType=*/protocol,
          /*packetType=*/static_cast<uint8_t>(type),
          /*srcMac=*/srcMac,
          /*dstMac=*/dstMac,
          /*ipSrc=*/ip.GetSource (),
          /*ipDst=*/ip.GetDestination ());

sendPkt->AddHeader (meta);

if (m_socket)
{
  m_socket->SendTo (sendPkt, 0, InetSocketAddress (m_peer, m_port));
}

return true;
}


// --------------------------------------------------------
// TunnelRecv: P2P (UDP) 経由で受け取ったパケットを無線に再注入
//   再注入前に WhTag を付けることで、逆側 WH の PromiscSniff でスキップできる
// --------------------------------------------------------
void
WormholeApp::TunnelRecv (Ptr<Socket> socket)
{
  Address from;
  Ptr<Packet> pkt = socket->RecvFrom (from);
  if (!pkt) return;

  // 1) メタヘッダを取り出す
  WhTunnelHeader meta;
  if (!pkt->RemoveHeader (meta))
    return;

  // 2) 以降 pkt は「元のIPv4パケット」先頭に戻っている想定

  // ---- IP/UDP/AODV を解析（必要なら改変）----
  Ipv4Header ip;
  if (!pkt->RemoveHeader (ip))
    return;

  // UDPでない場合：ForwardMode=0ならそのまま再注入、ForwardMode=1なら対象外なのでdrop
  if (ip.GetProtocol () != UdpL4Protocol::PROT_NUMBER)
  {
    if (m_forwardMode == 1)
      return;

    pkt->AddHeader (ip);
    WhTag tag; pkt->AddPacketTag (tag);
    m_dev->Send (pkt, meta.GetDstMac (), meta.GetEtherType ());
    return;
  }

UdpHeader udp;
  if (!pkt->RemoveHeader (udp))
    return;

  // AODV以外：ForwardMode=0ならそのまま再注入、ForwardMode=1ならdrop
  const bool isAodv =
      (udp.GetDestinationPort () == aodv::RoutingProtocol::AODV_PORT ||
       udp.GetSourcePort      () == aodv::RoutingProtocol::AODV_PORT);

  if (!isAodv)
    {
      if (m_forwardMode == 1)
        return;

      pkt->AddHeader (udp);
      pkt->AddHeader (ip);
      WhTag tag; pkt->AddPacketTag (tag);
      m_dev->Send (pkt, meta.GetDstMac (), meta.GetEtherType ());
      return;
    }

  // ここからAODV：タイプ判定
  aodv::TypeHeader type;
  if (!pkt->RemoveHeader (type))
    return;

  // ForwardMode=1：RREQ/RREP(Hello除外)以外はdrop
  if (m_forwardMode == 1)
    {
      bool allow = false;
      if (type.Get () == aodv::AODVTYPE_RREQ)
        {
          allow = true;
        }
      else if (type.Get () == aodv::AODVTYPE_RREP)
        {
          aodv::RrepHeader rrepCheck;
          if (!pkt->RemoveHeader (rrepCheck))
            return;

          if (IsHelloRrep (rrepCheck, ip))
            return; // ★Helloは再注入しない

          // 判定のため一度外したので戻しておく（後で改変処理があるため）
          pkt->AddHeader (rrepCheck);
          allow = true;
        }

      if (!allow)
        return;
    }

  // ---- AODV type を見てあなたのWHForwardFlag処理を維持 ----
  if (type.Get () == aodv::AODVTYPE_RREQ)
    {
      aodv::RreqHeader rreq;
      if (pkt->RemoveHeader (rreq))
        {
          rreq.SetWHForwardFlag (1);
          pkt->AddHeader (rreq);
        }
      pkt->AddHeader (type);
    }
  else if (type.Get () == aodv::AODVTYPE_RREP)
    {
      aodv::RrepHeader rrep;
      if (pkt->RemoveHeader (rrep))
        {
          // ★ForwardMode=1ではHelloは既にdrop済み
          rrep.SetWHForwardFlag (1);
          pkt->AddHeader (rrep);
        }
      pkt->AddHeader (type);
    }
  else
    {
      pkt->AddHeader (type);
    }

  // 3) ユニキャスト制御の再注入調整（元コード維持）
  Address l2dst = meta.GetDstMac ();
  if (meta.GetPacketType () == static_cast<uint8_t>(NetDevice::PACKET_HOST))
    {
      ip.SetDestination (Ipv4Address ("255.255.255.255"));
      l2dst = Mac48Address::GetBroadcast ();
    }

  // UDP/IP を戻す
  pkt->AddHeader (udp);
  pkt->AddHeader (ip);

  // 4) ループ防止タグを付けて再注入
  WhTag loopTag;
  pkt->AddPacketTag (loopTag);

  // 5) 再注入
  m_dev->Send (pkt, l2dst, meta.GetEtherType ());
}

//追加実装
NS_OBJECT_ENSURE_REGISTERED (WhTunnelHeader);

TypeId
WhTunnelHeader::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::WhTunnelHeader")
    .SetParent<Header> ()
    .SetGroupName ("Wormhole")
    .AddConstructor<WhTunnelHeader> ();
  return tid;
}

TypeId
WhTunnelHeader::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}

void
WhTunnelHeader::Set (uint16_t etherType,
                     uint8_t packetType,
                     Mac48Address src,
                     Mac48Address dst,
                     Ipv4Address ipSrc,
                     Ipv4Address ipDst)
{
  m_etherType   = etherType;
  m_packetType  = packetType;
  m_src         = src;
  m_dst         = dst;
  m_ipSrc       = ipSrc;
  m_ipDst       = ipDst;
}

uint32_t
WhTunnelHeader::GetSerializedSize (void) const
{
  // etherType(2) + packetType(1) + srcMac(6) + dstMac(6) + ipSrc(4) + ipDst(4)
  return 2 + 1 + 6 + 6 + 4 + 4;
}

void
WhTunnelHeader::Serialize (Buffer::Iterator i) const
{
  i.WriteHtonU16 (m_etherType);
  i.WriteU8 (m_packetType);

  uint8_t buf[6];
  m_src.CopyTo (buf);
  i.Write (buf, 6);

  m_dst.CopyTo (buf);
  i.Write (buf, 6);

  i.WriteHtonU32 (m_ipSrc.Get ());
  i.WriteHtonU32 (m_ipDst.Get ());
}

uint32_t
WhTunnelHeader::Deserialize (Buffer::Iterator i)
{
  m_etherType  = i.ReadNtohU16 ();
  m_packetType = i.ReadU8 ();

  uint8_t buf[6];
  i.Read (buf, 6);
  m_src.CopyFrom (buf);

  i.Read (buf, 6);
  m_dst.CopyFrom (buf);

  m_ipSrc = Ipv4Address (i.ReadNtohU32 ());
  m_ipDst = Ipv4Address (i.ReadNtohU32 ());

  return GetSerializedSize ();
}

void
WhTunnelHeader::Print (std::ostream &os) const
{
  os << "eth=0x" << std::hex << m_etherType << std::dec
     << " type=" << unsigned(m_packetType)
     << " srcMac=" << m_src
     << " dstMac=" << m_dst
     << " ipSrc=" << m_ipSrc
     << " ipDst=" << m_ipDst;
}

}
