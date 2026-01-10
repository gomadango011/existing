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

// ==============================
// WormholeApp 実装
// ==============================

NS_OBJECT_ENSURE_REGISTERED (WormholeApp);

TypeId
WormholeApp::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::WormholeApp")
    .SetParent<Application> ()
    .SetGroupName ("Wormhole")
    .AddConstructor<WormholeApp> ();
  return tid;
}

WormholeApp::WormholeApp ()
  : m_dev (0),
    m_socket (0),
    m_peer (),
    m_port (0)
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

  if (ip.GetProtocol () != UdpL4Protocol::PROT_NUMBER)
    return true;

  copy->RemoveHeader (ip);
  UdpHeader udp;
  if (!copy->PeekHeader (udp))
    return true;

  // AODVポート以外は無視
  if (udp.GetDestinationPort () != aodv::RoutingProtocol::AODV_PORT &&
      udp.GetSourcePort      () != aodv::RoutingProtocol::AODV_PORT)
    return true;

  // ここからトンネル送信：元のパケット（IPヘッダ等を壊してない方）に
  // L2/IP 情報を付けた WhTunnelHeader を先頭に追加する
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

  if (ip.GetProtocol () != UdpL4Protocol::PROT_NUMBER)
    {
      // UDPでないならそのまま戻して送る（必要ならdropでもOK）
      pkt->AddHeader (ip);
      WhTag tag; pkt->AddPacketTag (tag);
      m_dev->Send (pkt, meta.GetDstMac (), meta.GetEtherType ());
      return;
    }

  UdpHeader udp;
  if (!pkt->RemoveHeader (udp))
    return;

  // AODV以外ならそのまま戻して送る
  if (udp.GetDestinationPort () != ns3::aodv::RoutingProtocol::AODV_PORT &&
      udp.GetSourcePort      () != ns3::aodv::RoutingProtocol::AODV_PORT)
    {
      pkt->AddHeader (udp);
      pkt->AddHeader (ip);
      WhTag tag; pkt->AddPacketTag (tag);
      m_dev->Send (pkt, meta.GetDstMac (), meta.GetEtherType ());
      return;
    }

  // AODV type を見て処理（あなたのRREQ処理を維持）
  ns3::aodv::TypeHeader type;
  if (pkt->RemoveHeader (type))
    {
      if (type.Get () == ns3::aodv::AODVTYPE_RREQ)
        {
          ns3::aodv::RreqHeader rreq;
          if (pkt->RemoveHeader (rreq))
            {
              rreq.SetWHForwardFlag (1);
              pkt->AddHeader (rreq);
            }
          pkt->AddHeader (type);
        }else if(type.Get () == ns3::aodv::AODVTYPE_RREP)
        {
          ns3::aodv::RrepHeader rrep;
          if (pkt->RemoveHeader (rrep))
            {
              rrep.SetWHForwardFlag (1);
              pkt->AddHeader (rrep);
            }
          pkt->AddHeader (type);
        }
      else
        {
          pkt->AddHeader (type);
        }
    }
  else
    {
      // TypeHeaderが取れないなら戻せないのでここではdrop推奨
      // ただしあなたのコード方針に合わせるならそのままでもOK
      return;
    }

  // 3) “ユニキャストAODV制御も相手側で受信される” ように調整
  //
  // 元がユニキャスト(PACKET_HOST)の場合、元のIP宛先は WHノード自身になりやすく、
  // そのまま相手側に再注入しても誰も処理しない。
  // → 宛先を全体ブロードキャストへ変更して、近傍ノード群がAODVとして受信できるようにする。
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

  // 5) 再注入（L2宛先は上で決めたもの）
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
