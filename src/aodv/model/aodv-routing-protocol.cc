/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2009 IITP RAS
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Based on
 *      NS-2 AODV model developed by the CMU/MONARCH group and optimized and
 *      tuned by Samir Das and Mahesh Marina, University of Cincinnati;
 *
 *      AODV-UU implementation by Erik Nordström of Uppsala University
 *      http://core.it.uu.se/core/index.php/AODV-UU
 *
 * Authors: Elena Buchatskaia <borovkovaes@iitp.ru>
 *          Pavel Boyko <boyko@iitp.ru>
 */
#define NS_LOG_APPEND_CONTEXT                                   \
  if (m_ipv4) { std::clog << "[node " << m_ipv4->GetObject<Node> ()->GetId () << "] "; }

#include "aodv-routing-protocol.h"
#include "ns3/log.h"
#include "ns3/boolean.h"
#include "ns3/random-variable-stream.h"
#include "ns3/inet-socket-address.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/udp-l4-protocol.h"
#include "ns3/udp-header.h"
#include "ns3/wifi-net-device.h"
#include "ns3/adhoc-wifi-mac.h"
#include "ns3/string.h"
#include "ns3/pointer.h"
#include <algorithm>
#include <limits>

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("AodvRoutingProtocol");

namespace aodv {
NS_OBJECT_ENSURE_REGISTERED (RoutingProtocol);

/// UDP Port for AODV control traffic
const uint32_t RoutingProtocol::AODV_PORT = 654;

/**
* \ingroup aodv
* \brief Tag used by AODV implementation
*/
class DeferredRouteOutputTag : public Tag
{

public:
  /**
   * \brief Constructor
   * \param o the output interface
   */
  DeferredRouteOutputTag (int32_t o = -1) : Tag (),
                                            m_oif (o)
  {
  }

  /**
   * \brief Get the type ID.
   * \return the object TypeId
   */
  static TypeId GetTypeId ()
  {
    static TypeId tid = TypeId ("ns3::aodv::DeferredRouteOutputTag")
      .SetParent<Tag> ()
      .SetGroupName ("Aodv")
      .AddConstructor<DeferredRouteOutputTag> ()
    ;
    return tid;
  }

  TypeId  GetInstanceTypeId () const
  {
    return GetTypeId ();
  }

  /**
   * \brief Get the output interface
   * \return the output interface
   */
  int32_t GetInterface () const
  {
    return m_oif;
  }

  /**
   * \brief Set the output interface
   * \param oif the output interface
   */
  void SetInterface (int32_t oif)
  {
    m_oif = oif;
  }

  uint32_t GetSerializedSize () const
  {
    return sizeof(int32_t);
  }

  void  Serialize (TagBuffer i) const
  {
    i.WriteU32 (m_oif);
  }

  void  Deserialize (TagBuffer i)
  {
    m_oif = i.ReadU32 ();
  }

  void  Print (std::ostream &os) const
  {
    os << "DeferredRouteOutputTag: output interface = " << m_oif;
  }

private:
  /// Positive if output device is fixed in RouteOutput
  int32_t m_oif;
};

NS_OBJECT_ENSURE_REGISTERED (DeferredRouteOutputTag);


//-----------------------------------------------------------------------------
RoutingProtocol::RoutingProtocol ()
  : m_rreqRetries (2),// RREQの最大再送信回数
    m_ttlStart (1),//TTL（パケットの寿命）
    m_ttlIncrement (2),//TTLのインクリメント
    m_ttlThreshold (7),//最大のTTｌ値
    m_timeoutBuffer (2),//タイムアウト用のバッファを用意
    m_rreqRateLimit (10),//RREQの一秒あたりの最大値
    m_rerrRateLimit (10),//RRERの一秒あたりの最大値
    m_activeRouteTimeout (Seconds (3)),//ルートが有効とみなされる期間
    m_netDiameter (35),//ネットワーク内の最大ホップ数
    m_nodeTraversalTime (MilliSeconds (40)),//パケットの１ホップあたりのトラバーサルタイムの推定値
    m_netTraversalTime (Time ((2 * m_netDiameter) * m_nodeTraversalTime)),//平均トラバーサルタイムの見積もり
    m_pathDiscoveryTime ( Time (2 * m_netTraversalTime)),//経路発見に必要な最大時間の見積もり
    m_myRouteTimeout (Time (2 * std::max (m_pathDiscoveryTime, m_activeRouteTimeout))),//ノードが生成するRREPの寿命の値
    m_helloInterval (Seconds (1)),//helloインターバル
    m_allowedHelloLoss (2),//有効なリンクが失われている可能性があるhelloメッセージ
    m_deletePeriod (Time (5 * std::max (m_activeRouteTimeout, m_helloInterval))),//DeletePeriod??
    m_nextHopWait (m_nodeTraversalTime + MilliSeconds (10)),//隣からのRREP_ACKを待つ期間。
    m_blackListTimeout (Time (m_rreqRetries * m_netTraversalTime)),//ノードがブラックリストに登録された時間
    m_maxQueueLen (64),//ルーティングプロトコルがバッファすることを許可するパケットの最大数。
    m_maxQueueTime (Seconds (30)),//ルーティング・プロトコルがパケットをバッファリングすることが許される最大時間。
    m_destinationOnly (true),//宛先のみがこのRREQに応答できることを示す。
    m_gratuitousReply (true),//RREPをルート探索を行ったノードにユニキャストすべきかどうかを示す。
    m_enableHello (false),//ハローメッセージが有効かどうかを示す。
    m_routingTable (m_deletePeriod),//ルーティングテーブル
    m_queue (m_maxQueueLen, m_maxQueueTime),//ルーティングレイヤーが経路を持たないパケットをバッファリングするために使用する「ドロップフロント」キュー。
    m_requestId (0),//ブロードキャストID
    m_seqNo (0),//リクエスト・シーケンス番号
    m_rreqIdCache (m_pathDiscoveryTime),//重複したRREQを処理する
    m_WHEIdCache (m_pathDiscoveryTime),
    m_dpd (m_pathDiscoveryTime),//ブロードキャスト/マルチキャストパケットの重複処理
    m_nb (m_helloInterval),//隣接ノードへの対応
    m_rreqCount (0),//RREQレート制御に使用されるRREQ数
    m_rerrCount (0),//RRERレート制御に使用されるRREQ数
    m_htimer (Timer::CANCEL_ON_DESTROY),//helloタイマー
    m_rreqRateLimitTimer (Timer::CANCEL_ON_DESTROY),//RREQのリミットタイマー
    m_rerrRateLimitTimer (Timer::CANCEL_ON_DESTROY),//RRERのリミットタイマー
    m_lastBcastTime (Seconds (0)),//最後のブロードキャスト時間を追跡する

    Rrep_List {},
    WH_List {Ipv4Address("10.0.0.2"), Ipv4Address("10.0.0.3")},

    WH_Flag (0),
    get_rreptimes (0),
    WH1 (0),
    WH2 (0),
    rrepid (0)

    
{
  if (m_enableHello)
  {
    //リンク失敗時のコールバックの設定　　RRERを開智する
    m_nb.SetCallback (MakeCallback (&RoutingProtocol::SendRerrWhenBreaksLinkToNextHop, this));
  }
}
TypeId
RoutingProtocol::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::aodv::RoutingProtocol")
    .SetParent<Ipv4RoutingProtocol> () //親子関係の設定
    .SetGroupName ("Aodv")
    .AddConstructor<RoutingProtocol> ()
    .AddAttribute ("HelloInterval", "HELLO messages emission interval.", //AddAttribute=渡したいデータをオブジェクトに追加する
                   TimeValue (Seconds (1)),
                   MakeTimeAccessor (&RoutingProtocol::m_helloInterval),
                   MakeTimeChecker ())
    .AddAttribute ("TtlStart", "Initial TTL value for RREQ.",
                   UintegerValue (1),
                   MakeUintegerAccessor (&RoutingProtocol::m_ttlStart),
                   MakeUintegerChecker<uint16_t> ())
    .AddAttribute ("TtlIncrement", "TTL increment for each attempt using the expanding ring search for RREQ dissemination.",
                   UintegerValue (2),
                   MakeUintegerAccessor (&RoutingProtocol::m_ttlIncrement),
                   MakeUintegerChecker<uint16_t> ())
    .AddAttribute ("TtlThreshold", "Maximum TTL value for expanding ring search, TTL = NetDiameter is used beyond this value.",
                   UintegerValue (7),
                   MakeUintegerAccessor (&RoutingProtocol::m_ttlThreshold),
                   MakeUintegerChecker<uint16_t> ())
    .AddAttribute ("TimeoutBuffer", "Provide a buffer for the timeout.",
                   UintegerValue (2),
                   MakeUintegerAccessor (&RoutingProtocol::m_timeoutBuffer),
                   MakeUintegerChecker<uint16_t> ())
    .AddAttribute ("RreqRetries", "Maximum number of retransmissions of RREQ to discover a route",
                   UintegerValue (2),
                   MakeUintegerAccessor (&RoutingProtocol::m_rreqRetries),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("RreqRateLimit", "Maximum number of RREQ per second.",
                   UintegerValue (10),
                   MakeUintegerAccessor (&RoutingProtocol::m_rreqRateLimit),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("RerrRateLimit", "Maximum number of RERR per second.",
                   UintegerValue (10),
                   MakeUintegerAccessor (&RoutingProtocol::m_rerrRateLimit),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("NodeTraversalTime", "Conservative estimate of the average one hop traversal time for packets and should include "
                   "queuing delays, interrupt processing times and transfer times.",
                   TimeValue (MilliSeconds (40)),
                   MakeTimeAccessor (&RoutingProtocol::m_nodeTraversalTime),
                   MakeTimeChecker ())
    .AddAttribute ("NextHopWait", "Period of our waiting for the neighbour's RREP_ACK = 10 ms + NodeTraversalTime",
                   TimeValue (MilliSeconds (50)),
                   MakeTimeAccessor (&RoutingProtocol::m_nextHopWait),
                   MakeTimeChecker ())
    .AddAttribute ("ActiveRouteTimeout", "Period of time during which the route is considered to be valid",
                   TimeValue (Seconds (3)),
                   MakeTimeAccessor (&RoutingProtocol::m_activeRouteTimeout),
                   MakeTimeChecker ())
    .AddAttribute ("MyRouteTimeout", "Value of lifetime field in RREP generating by this node = 2 * max(ActiveRouteTimeout, PathDiscoveryTime)",
                   TimeValue (Seconds (11.2)),
                   MakeTimeAccessor (&RoutingProtocol::m_myRouteTimeout),
                   MakeTimeChecker ())
    .AddAttribute ("BlackListTimeout", "Time for which the node is put into the blacklist = RreqRetries * NetTraversalTime",
                   TimeValue (Seconds (5.6)),
                   MakeTimeAccessor (&RoutingProtocol::m_blackListTimeout),
                   MakeTimeChecker ())
    .AddAttribute ("DeletePeriod", "DeletePeriod is intended to provide an upper bound on the time for which an upstream node A "
                   "can have a neighbor B as an active next hop for destination D, while B has invalidated the route to D."
                   " = 5 * max (HelloInterval, ActiveRouteTimeout)",
                   TimeValue (Seconds (15)),
                   MakeTimeAccessor (&RoutingProtocol::m_deletePeriod),
                   MakeTimeChecker ())
    .AddAttribute ("NetDiameter", "Net diameter measures the maximum possible number of hops between two nodes in the network",
                   UintegerValue (35),
                   MakeUintegerAccessor (&RoutingProtocol::m_netDiameter),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("NetTraversalTime", "Estimate of the average net traversal time = 2 * NodeTraversalTime * NetDiameter",
                   TimeValue (Seconds (2.8)),
                   MakeTimeAccessor (&RoutingProtocol::m_netTraversalTime),
                   MakeTimeChecker ())
    .AddAttribute ("PathDiscoveryTime", "Estimate of maximum time needed to find route in network = 2 * NetTraversalTime",
                   TimeValue (Seconds (5.6)),
                   MakeTimeAccessor (&RoutingProtocol::m_pathDiscoveryTime),
                   MakeTimeChecker ())
    .AddAttribute ("MaxQueueLen", "Maximum number of packets that we allow a routing protocol to buffer.",
                   UintegerValue (64),
                   MakeUintegerAccessor (&RoutingProtocol::SetMaxQueueLen,
                                         &RoutingProtocol::GetMaxQueueLen),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("MaxQueueTime", "Maximum time packets can be queued (in seconds)",
                   TimeValue (Seconds (30)),
                   MakeTimeAccessor (&RoutingProtocol::SetMaxQueueTime,
                                     &RoutingProtocol::GetMaxQueueTime),
                   MakeTimeChecker ())
    .AddAttribute ("AllowedHelloLoss", "Number of hello messages which may be loss for valid link.",
                   UintegerValue (2),
                   MakeUintegerAccessor (&RoutingProtocol::m_allowedHelloLoss),
                   MakeUintegerChecker<uint16_t> ())
    .AddAttribute ("GratuitousReply", "Indicates whether a gratuitous RREP should be unicast to the node originated route discovery.",
                   BooleanValue (true),
                   MakeBooleanAccessor (&RoutingProtocol::SetGratuitousReplyFlag,
                                        &RoutingProtocol::GetGratuitousReplyFlag),
                   MakeBooleanChecker ())
    .AddAttribute ("DestinationOnly", "Indicates only the destination may respond to this RREQ.",
                   BooleanValue (false),
                   MakeBooleanAccessor (&RoutingProtocol::SetDestinationOnlyFlag,
                                        &RoutingProtocol::GetDestinationOnlyFlag),
                   MakeBooleanChecker ())
    .AddAttribute ("EnableHello", "Indicates whether a hello messages enable.",
                   BooleanValue (true),
                   MakeBooleanAccessor (&RoutingProtocol::SetHelloEnable,
                                        &RoutingProtocol::GetHelloEnable),
                   MakeBooleanChecker ())
    .AddAttribute ("EnableBroadcast", "Indicates whether a broadcast data packets forwarding enable.",
                   BooleanValue (true),
                   MakeBooleanAccessor (&RoutingProtocol::SetBroadcastEnable,
                                        &RoutingProtocol::GetBroadcastEnable),
                   MakeBooleanChecker ())
    .AddAttribute ("UniformRv",
                   "Access to the underlying UniformRandomVariable",
                   StringValue ("ns3::UniformRandomVariable"),
                   MakePointerAccessor (&RoutingProtocol::m_uniformRandomVariable),
                   MakePointerChecker<UniformRandomVariable> ())
  ;
  return tid;
}

void
RoutingProtocol::SetMaxQueueLen (uint32_t len)//最大のキューの長さの設定
{
  m_maxQueueLen = len;
  m_queue.SetMaxQueueLen (len);
}
void
RoutingProtocol::SetMaxQueueTime (Time t)//最大キューの時間設定
{
  m_maxQueueTime = t;
  m_queue.SetQueueTimeout (t);
}

RoutingProtocol::~RoutingProtocol ()
{
}

void
RoutingProtocol::DoDispose () //クラス・オブジェクトの破棄
{
  m_ipv4 = 0;
  //std::map : 並行二分木　　iterator : コンテナ内での要素の一を示すもの
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::iterator iter =
         m_socketAddresses.begin (); iter != m_socketAddresses.end (); iter++)
    {
      iter->first->Close ();
    }
  m_socketAddresses.clear ();
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::iterator iter =
         m_socketSubnetBroadcastAddresses.begin (); iter != m_socketSubnetBroadcastAddresses.end (); iter++)
    {
      iter->first->Close ();
    }
  m_socketSubnetBroadcastAddresses.clear ();
  Ipv4RoutingProtocol::DoDispose ();
}


//PrintRoutingTable : ルーティングテーブルのエントリを出力
void
RoutingProtocol::PrintRoutingTable (Ptr<OutputStreamWrapper> stream, Time::Unit unit) const
{
  *stream->GetStream () << "Node: " << m_ipv4->GetObject<Node> ()->GetId ()
                        << "; Time: " << Now ().As (unit)
                        << ", Local time: " << GetObject<Node> ()->GetLocalTime ().As (unit)
                        << ", AODV Routing table" << std::endl;

  m_routingTable.Print (stream);
  *stream->GetStream () << std::endl;
}

// このモデルで使用される確率変数に固定の確率変数ストリーム番号を割り当てます。
int64_t
RoutingProtocol::AssignStreams (int64_t stream)
{
  NS_LOG_FUNCTION (this << stream);
  m_uniformRandomVariable->SetStream (stream);
  return 1;
}


//ルーティングプロトコルスタート
void
RoutingProtocol::Start ()
{
  NS_LOG_FUNCTION (this);
  if (m_enableHello)
    {
      m_nb.ScheduleTimer ();
    }
  m_rreqRateLimitTimer.SetFunction (&RoutingProtocol::RreqRateLimitTimerExpire, //RREQカウントをリセットし、RREQレート制限タイマーを遅延1秒でスケジュールする。
                                    this);
  m_rreqRateLimitTimer.Schedule (Seconds (1));

  m_rerrRateLimitTimer.SetFunction (&RoutingProtocol::RerrRateLimitTimerExpire,
                                    this);
  m_rerrRateLimitTimer.Schedule (Seconds (1));

}

Ptr<Ipv4Route>
//送信パケットの既存のルートのルーティング キャッシュをクエリします。
//ルーティングプロトコル側のこのメソッドを呼び出して、転送経路を決定してもらう。
RoutingProtocol::RouteOutput (Ptr<Packet> p/*経路決定する必要のあるパケット*/, 
                              const Ipv4Header &header/*経路決定するためのヘッダ情報*/,
                              Ptr<NetDevice> oif/*出力用インターフェース*/, 
                              Socket::SocketErrno &sockerr/*ソケットのエラーコード(出力パラメータ)*/)
{
  NS_LOG_FUNCTION (this << header << (oif ? oif->GetIfIndex () : 0));
  if (!p)
    {
      NS_LOG_DEBUG ("Packet is == 0");
      return LoopbackRoute (header, oif); // later
    }
  if (m_socketAddresses.empty ())
    {
      sockerr = Socket::ERROR_NOROUTETOHOST;
      NS_LOG_LOGIC ("No aodv interfaces");
      Ptr<Ipv4Route> route;
      return route;
    }
  sockerr = Socket::ERROR_NOTERROR;
  Ptr<Ipv4Route> route;
  //GetDestination : 目的地取得？？
  Ipv4Address dst = header.GetDestination ();
  RoutingTableEntry rt;  //ルーティング テーブルのエントリ
  if (m_routingTable.LookupValidRoute (dst, rt)) // 有効な状態のルートを検索
    {
      route = rt.GetRoute (); //GetRoute : ルート取得関数, RREP_ACK タイマー。
      NS_ASSERT (route != 0);
      //GetDestination : 目的地取得？？　　GetSource : ソースノード取得？？
      NS_LOG_DEBUG ("Exist route to " << route->GetDestination () << " from interface " << route->GetSource ());
      if (oif != 0 && route->GetOutputDevice () != oif)//GetOutputDevice  : パケットの送信ノードを取得？？
        {
          NS_LOG_DEBUG ("Output device doesn't match. Dropped.");
          sockerr = Socket::ERROR_NOROUTETOHOST;
          return Ptr<Ipv4Route> ();
        }
      UpdateRouteLifeTime (dst, m_activeRouteTimeout);//目的地までのルートの寿命を更新
      UpdateRouteLifeTime (route->GetGateway (), m_activeRouteTimeout);//ゲートウェイノードまでのルートの寿命を更新
      return route;
    }

  // 有効なルートが見つからない場合、ループバックを返します。
  // A実際のルートリクエストは、パケットが完全に形成され、ループバックへルーティングされ、
  //ループバックから受信され、RouteInputに渡されるまで延期される（以下を参照）。
  uint32_t iif = (oif ? m_ipv4->GetInterfaceForDevice (oif) : -1);
  DeferredRouteOutputTag tag (iif);
  NS_LOG_DEBUG ("Valid Route not found");
  if (!p->PeekPacketTag (tag))
    {
      p->AddPacketTag (tag);
    }
  return LoopbackRoute (header, oif);
}

//パケットをキューに入れてルート要求を送信します。
void
RoutingProtocol::DeferredRouteOutput (Ptr<const Packet> p, const Ipv4Header & header,
                                      UnicastForwardCallback ucb, ErrorCallback ecb)
{
  NS_LOG_FUNCTION (this << p << header);
  NS_ASSERT (p != 0 && p != Ptr<Packet> ()); //状態を確認する

  QueueEntry newEntry (p, header, ucb, ecb);//AODVキューエントリ
  bool result = m_queue.Enqueue (newEntry);//ルートを持たないパケットをバッファリングするために利用する
  if (result)
    {
      NS_LOG_LOGIC ("Add packet " << p->GetUid () << " to queue. Protocol " << (uint16_t) header.GetProtocol ());
      RoutingTableEntry rt;
      bool result = m_routingTable.LookupRoute (header.GetDestination (), rt);//宛先アドレスを使用してルーティングテーブルエントリを検索
      if (!result || ((rt.GetFlag () != IN_SEARCH) && result))
        {
          NS_LOG_LOGIC ("Send new RREQ for outbound packet to " << header.GetDestination ());
          SendRequest (header.GetDestination ());
        }
    }
}

//入力パケットをルーティングします 
bool
RoutingProtocol::RouteInput (Ptr<const Packet> p, const Ipv4Header &header,//IPV4のパケットヘッダ
                             Ptr<const NetDevice> idev, UnicastForwardCallback ucb,
                             MulticastForwardCallback mcb, LocalDeliverCallback lcb, ErrorCallback ecb)
{
  NS_LOG_FUNCTION (this << p->GetUid () << header.GetDestination () << idev->GetAddress ());
  if (m_socketAddresses.empty ())
    {
      NS_LOG_LOGIC ("No aodv interfaces");
      return false;
    }
  NS_ASSERT (m_ipv4 != 0);
  NS_ASSERT (p != 0);
  // 入力デバイスがIPをサポートしているか確認する
  NS_ASSERT (m_ipv4->GetInterfaceForDevice (idev) >= 0);
  int32_t iif = m_ipv4->GetInterfaceForDevice (idev);

  Ipv4Address dst = header.GetDestination ();
  Ipv4Address origin = header.GetSource ();

  // 遅延ルートリクエスト
  if (idev == m_lo)
    {
      DeferredRouteOutputTag tag;
      if (p->PeekPacketTag (tag))
        {
          DeferredRouteOutput (p, header, ucb, ecb);
          return true;
        }
    }

  // 自分のパケットの複製
  if (IsMyOwnAddress (origin))
    {
      return true;
    }

  //AODVはマルチキャストルーティングプロトコルではない
  if (dst.IsMulticast ())
    {
      return false;
    }

  // ブロードキャスト・ローカル・デリバリー／フォワーディング
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j =
         m_socketAddresses.begin (); j != m_socketAddresses.end (); ++j)
    {
      Ipv4InterfaceAddress iface = j->second;
      if (m_ipv4->GetInterfaceForAddress (iface.GetLocal ()) == iif) //GetInterfaceForAddress : 	指定された IP アドレスが割り当てられているインターフェイスのインターフェイス番号を返します
        {
          if (dst == iface.GetBroadcast () || dst.IsBroadcast ())
            {
              if (m_dpd.IsDuplicate (p, header))// キャッシュにエントリ (addr、id) が存在することを確認します。
                {
                  NS_LOG_DEBUG ("Duplicated packet " << p->GetUid () << " from " << origin << ". Drop.");
                  return true;
                }
              UpdateRouteLifeTime (origin, m_activeRouteTimeout);
              Ptr<Packet> packet = p->Copy ();
              if (lcb.IsNull () == false)
                {
                  NS_LOG_LOGIC ("Broadcast local delivery to " << iface.GetLocal ());
                  lcb (p, header, iif);
                  // 追加処理に進む
                }
              else
                {
                  NS_LOG_ERROR ("Unable to deliver packet locally due to null callback " << p->GetUid () << " from " << origin);
                  ecb (p, header, Socket::ERROR_NOROUTETOHOST);
                }
              if (!m_enableBroadcast)
                {
                  return true;
                }
              if (header.GetProtocol () == UdpL4Protocol::PROT_NUMBER)//GetProtocol : 上位に当たるトランスポート層のネットワーク・プロトコルの種類を表す番号を格納するフィールド
                {
                  UdpHeader udpHeader;
                  p->PeekHeader (udpHeader);
                  if (udpHeader.GetDestinationPort () == AODV_PORT)
                    {
                      // ブロードキャストで送信されたAODVパケットはすでに管理されている
                      return true;
                    }
                }
              if (header.GetTtl () > 1)
                {
                  NS_LOG_LOGIC ("Forward broadcast. TTL " << (uint16_t) header.GetTtl ());
                  RoutingTableEntry toBroadcast;
                  if (m_routingTable.LookupRoute (dst, toBroadcast))//宛先
                    {
                      Ptr<Ipv4Route> route = toBroadcast.GetRoute ();
                      ucb (route, packet, header);
                    }
                  else
                    {
                      NS_LOG_DEBUG ("No route to forward broadcast. Drop packet " << p->GetUid ());
                    }
                }
              else
                {
                  NS_LOG_DEBUG ("TTL exceeded. Drop packet " << p->GetUid ());
                }
              return true;
            }
        }
    }

  // ユニキャストローカル配信
  if (m_ipv4->IsDestinationAddress (dst, iif))//受信したパケットに対応するアドレスとインターフェイスがローカル配信に受け入れられるかどうかを判断します。
    {
      UpdateRouteLifeTime (origin, m_activeRouteTimeout);//originまでのルートの寿命を更新
      RoutingTableEntry toOrigin;//ルーティングテーブルのエントリ
      if (m_routingTable.LookupValidRoute (origin, toOrigin))//送信元ノードへの有効なルートを検索
        {
          UpdateRouteLifeTime (toOrigin.GetNextHop (), m_activeRouteTimeout);//ネクストホップまでの寿命を更新
          m_nb.Update (toOrigin.GetNextHop (), m_activeRouteTimeout);//隣接ノード二ネクストホップが存在する場合は更新し、しない場合にはエントリを追加
        }
      if (lcb.IsNull () == false)
        {
          NS_LOG_LOGIC ("Unicast local delivery to " << dst);
          lcb (p, header, iif);
        }
      else
        {
          NS_LOG_ERROR ("Unable to deliver packet locally due to null callback " << p->GetUid () << " from " << origin);
          ecb (p, header, Socket::ERROR_NOROUTETOHOST);
        }
      return true;
    }

  // 入力デバイスがIP転送をサポートしているか確認する
  if (m_ipv4->IsForwarding (iif) == false)
    {
      NS_LOG_LOGIC ("Forwarding disabled for this interface");
      ecb (p, header, Socket::ERROR_NOROUTETOHOST);
      return true;
    }

  // データ転送
  return Forwarding (p, header, ucb, ecb);
}

bool
RoutingProtocol::Forwarding (Ptr<const Packet> p, const Ipv4Header & header, //ルートが存在し、有効であれば、パケットを転送する。
                             UnicastForwardCallback ucb, ErrorCallback ecb)
{
  NS_LOG_FUNCTION (this);
  Ipv4Address dst = header.GetDestination ();
  Ipv4Address origin = header.GetSource ();
  m_routingTable.Purge ();//古くなったエントリをすべて削除
  RoutingTableEntry toDst;//ルーティングテーブルのエントリ
  if (m_routingTable.LookupRoute (dst, toDst))//宛先に対するルーティングテーブルのエントリを検索
    {
      if (toDst.GetFlag () == VALID)
        {
          Ptr<Ipv4Route> route = toDst.GetRoute ();
          NS_LOG_LOGIC (route->GetSource () << " forwarding to " << dst << " from " << origin << " packet " << p->GetUid ());

          /*
            ルートがデータパケットを転送するために使用されるたびに、
            ソース、デスティネー ション、およびデスティネーションへのパス上のネクストホップの
            Active Route Lifetimeフィールドは、現在時刻にActiveRouteTimeoutを加えた値以上
            に更新される。
           */
          UpdateRouteLifeTime (origin, m_activeRouteTimeout);//送信元に対するルートの寿命を更新
          UpdateRouteLifeTime (dst, m_activeRouteTimeout);//宛先に対するルートの寿命を更新
          UpdateRouteLifeTime (route->GetGateway (), m_activeRouteTimeout);//ゲートウェイノードに対するルートの寿命を更新
          /*
           各発信元と宛先のペア間のルートは対称であることが予想されるため、
           IPソースに戻るリバースパスに沿って、前のホップの*アクティブルート寿命も更新される。
           IPソースに戻るリバースパスに沿った前のホップのアクティブルート寿命も、
           現在時刻にActiveRouteTimeoutを加えた値以上になるように更新される。
           */
          RoutingTableEntry toOrigin;
          m_routingTable.LookupRoute (origin, toOrigin);
          UpdateRouteLifeTime (toOrigin.GetNextHop (), m_activeRouteTimeout);

          m_nb.Update (route->GetGateway (), m_activeRouteTimeout);
          m_nb.Update (toOrigin.GetNextHop (), m_activeRouteTimeout);

          ucb (route, p, header);//ユニキャストコールバック
          return true;
        }
      else
        {
          if (toDst.GetValidSeqNo ()) //有効なシーケンス番号を取得
            {
              SendRerrWhenNoRouteToForward (dst, toDst.GetSeqNo (), origin); //入力パケットを転送するルートがない場合に RERR メッセージを送信します。
              NS_LOG_DEBUG ("Drop packet " << p->GetUid () << " because no route to forward it.");
              return false;
            }
        }
    }
  NS_LOG_LOGIC ("route not found to " << dst << ". Send RERR message.");
  NS_LOG_DEBUG ("Drop packet " << p->GetUid () << " because no route to forward it.");
  SendRerrWhenNoRouteToForward (dst, 0, origin); //dst:宛先のIPアドレス、0:宛先ノードのシーケンス番号、origin:発信元のIPアドレス
  return false;
}

void
RoutingProtocol::SetIpv4 (Ptr<Ipv4> ipv4) //このルーティング プロトコルが関連付けられている ipv4 オブジェクト

{
  NS_ASSERT (ipv4 != 0); //実行時、デバッグ ビルドでこの条件が true でない場合、プログラムはソース ファイル、行番号、および未検証の条件を出力し、std::terminate を呼び出して停止します。
  NS_ASSERT (m_ipv4 == 0);

  m_ipv4 = ipv4;

  // loルートを作成する。現在アップしているインターフェイスはループバックだけです。
  NS_ASSERT (m_ipv4->GetNInterfaces () == 1 && m_ipv4->GetAddress (0, 0).GetLocal () == Ipv4Address ("127.0.0.1"));
  m_lo = m_ipv4->GetNetDevice (0);
  NS_ASSERT (m_lo != 0);
  // ロールートを覚えておく                                      //127.0.0.1アドレスを取得
  RoutingTableEntry rt (/*device=*/ m_lo, /*dst=*/ Ipv4Address::GetLoopback (), /*know seqno=*/ true, /*seqno=*/ 0,
                                    /*iface=*/ Ipv4InterfaceAddress (Ipv4Address::GetLoopback (), Ipv4Mask ("255.0.0.0")),
                                    /*hops=*/ 1, /*next hop=*/ Ipv4Address::GetLoopback (),
                                    /*lifetime=*/ Simulator::GetMaximumSimulationTime ());
  m_routingTable.AddRoute (rt); //ルーティングテーブルにまだ存在しない場合は、ルーティングテーブルエントリーを追加する。

  Simulator::ScheduleNow (&RoutingProtocol::Start, this); //今すぐ期限切れになるようにイベントをスケジュールします。　RoutingProtocol::start : プロトコルの動作を開始
}

void
RoutingProtocol::NotifyInterfaceUp (uint32_t i)//プロトコルは、ノード内のインターフェイスの状態変化を通知するために、このメソッドを実装することが期待されます。
{
  NS_LOG_FUNCTION (this << m_ipv4->GetAddress (i, 0).GetLocal ());
  Ptr<Ipv4L3Protocol> l3 = m_ipv4->GetObject<Ipv4L3Protocol> ();
  if (l3->GetNAddresses (i) > 1)
    {
      NS_LOG_WARN ("AODV does not work with more then one address per each interface.");
    }
  Ipv4InterfaceAddress iface = l3->GetAddress (i, 0);
  if (iface.GetLocal () == Ipv4Address ("127.0.0.1"))
    {
      return;
    }

  // このインターフェイスのみをリッスンするソケットを作成する
  Ptr<Socket> socket = Socket::CreateSocket (GetObject<Node> (),
                                             UdpSocketFactory::GetTypeId ());
  NS_ASSERT (socket != 0);
  socket->SetRecvCallback (MakeCallback (&RoutingProtocol::RecvAodv, this));
  socket->BindToNetDevice (l3->GetNetDevice (i));
  socket->Bind (InetSocketAddress (iface.GetLocal (), AODV_PORT));
  socket->SetAllowBroadcast (true);
  socket->SetIpRecvTtl (true);
  m_socketAddresses.insert (std::make_pair (socket, iface));

  // サブネットブロードキャストソケットも作成する
  socket = Socket::CreateSocket (GetObject<Node> (),
                                 UdpSocketFactory::GetTypeId ());
  NS_ASSERT (socket != 0);
  socket->SetRecvCallback (MakeCallback (&RoutingProtocol::RecvAodv, this));
  socket->BindToNetDevice (l3->GetNetDevice (i));
  socket->Bind (InetSocketAddress (iface.GetBroadcast (), AODV_PORT));
  socket->SetAllowBroadcast (true);
  socket->SetIpRecvTtl (true);
  m_socketSubnetBroadcastAddresses.insert (std::make_pair (socket, iface));

  // ルーティングテーブルにローカル・ブロードキャスト・レコードを追加する
  Ptr<NetDevice> dev = m_ipv4->GetNetDevice (m_ipv4->GetInterfaceForAddress (iface.GetLocal ()));
  RoutingTableEntry rt (/*device=*/ dev, /*dst=*/ iface.GetBroadcast (), /*know seqno=*/ true, /*seqno=*/ 0, /*iface=*/ iface,
                                    /*hops=*/ 1, /*next hop=*/ iface.GetBroadcast (), /*lifetime=*/ Simulator::GetMaximumSimulationTime ());
  m_routingTable.AddRoute (rt);

  if (l3->GetInterface (i)->GetArpCache ())
    {
      m_nb.AddArpCache (l3->GetInterface (i)->GetArpCache ());
    }

  // 可能であれば、ネイバー・マネージャーがこのインターフェイスをレイヤー2フィードバックに使用することを許可する。
  Ptr<WifiNetDevice> wifi = dev->GetObject<WifiNetDevice> ();
  if (wifi == 0)
    {
      return;
    }
  Ptr<WifiMac> mac = wifi->GetMac ();
  if (mac == 0)
    {
      return;
    }

  mac->TraceConnectWithoutContext ("TxErrHeader", m_nb.GetTxErrorCallback ());
}

void
RoutingProtocol::NotifyInterfaceDown (uint32_t i) //プロトコルは、ノード内のインターフェイスの状態変化を通知するために、このメソッドを実装することが期待されます。
{
  NS_LOG_FUNCTION (this << m_ipv4->GetAddress (i, 0).GetLocal ());

  // レイヤ2リンク状態監視を無効にする（可能な場合）
  Ptr<Ipv4L3Protocol> l3 = m_ipv4->GetObject<Ipv4L3Protocol> ();
  Ptr<NetDevice> dev = l3->GetNetDevice (i);
  Ptr<WifiNetDevice> wifi = dev->GetObject<WifiNetDevice> ();
  if (wifi != 0)
    {
      Ptr<WifiMac> mac = wifi->GetMac ()->GetObject<AdhocWifiMac> ();
      if (mac != 0)
        {
          mac->TraceDisconnectWithoutContext ("TxErrHeader",
                                              m_nb.GetTxErrorCallback ());
          m_nb.DelArpCache (l3->GetInterface (i)->GetArpCache ());
        }
    }

  // Close socket
  Ptr<Socket> socket = FindSocketWithInterfaceAddress (m_ipv4->GetAddress (i, 0));
  NS_ASSERT (socket);
  socket->Close ();
  m_socketAddresses.erase (socket);

  // Close socket
  socket = FindSubnetBroadcastSocketWithInterfaceAddress (m_ipv4->GetAddress (i, 0));
  NS_ASSERT (socket);
  socket->Close ();
  m_socketSubnetBroadcastAddresses.erase (socket);

  if (m_socketAddresses.empty ())
    {
      NS_LOG_LOGIC ("No aodv interfaces");
      m_htimer.Cancel ();
      m_nb.Clear ();
      m_routingTable.Clear ();
      return;
    }
  m_routingTable.DeleteAllRoutesFromInterface (m_ipv4->GetAddress (i, 0));
}

void
RoutingProtocol::NotifyAddAddress (uint32_t i, Ipv4InterfaceAddress address) //新しいアドレスがインターフェイスに追加されるたびに通知されるように、プロトコルはこのメソッドを実装することが期待されます。
{
  NS_LOG_FUNCTION (this << " interface " << i << " address " << address);
  Ptr<Ipv4L3Protocol> l3 = m_ipv4->GetObject<Ipv4L3Protocol> ();
  if (!l3->IsUp (i))
    {
      return;
    }
  if (l3->GetNAddresses (i) == 1)
    {
      Ipv4InterfaceAddress iface = l3->GetAddress (i, 0);
      Ptr<Socket> socket = FindSocketWithInterfaceAddress (iface);
      if (!socket)
        {
          if (iface.GetLocal () == Ipv4Address ("127.0.0.1"))
            {
              return;
            }
          // このインターフェイスのみをリッスンするソケットを作成する
          Ptr<Socket> socket = Socket::CreateSocket (GetObject<Node> (),
                                                     UdpSocketFactory::GetTypeId ());
          NS_ASSERT (socket != 0);
          socket->SetRecvCallback (MakeCallback (&RoutingProtocol::RecvAodv,this));
          socket->BindToNetDevice (l3->GetNetDevice (i));
          socket->Bind (InetSocketAddress (iface.GetLocal (), AODV_PORT));
          socket->SetAllowBroadcast (true);
          m_socketAddresses.insert (std::make_pair (socket, iface));

          // サブネット向けブロードキャストソケットも作成する
          socket = Socket::CreateSocket (GetObject<Node> (),
                                         UdpSocketFactory::GetTypeId ());
          NS_ASSERT (socket != 0);
          socket->SetRecvCallback (MakeCallback (&RoutingProtocol::RecvAodv, this));
          socket->BindToNetDevice (l3->GetNetDevice (i));
          socket->Bind (InetSocketAddress (iface.GetBroadcast (), AODV_PORT));
          socket->SetAllowBroadcast (true);
          socket->SetIpRecvTtl (true);
          m_socketSubnetBroadcastAddresses.insert (std::make_pair (socket, iface));

          // ルーティングテーブルにローカル・ブロードキャスト・レコードを追加する
          Ptr<NetDevice> dev = m_ipv4->GetNetDevice (
              m_ipv4->GetInterfaceForAddress (iface.GetLocal ()));
          RoutingTableEntry rt (/*device=*/ dev, /*dst=*/ iface.GetBroadcast (), /*know seqno=*/ true,
                                            /*seqno=*/ 0, /*iface=*/ iface, /*hops=*/ 1,
                                            /*next hop=*/ iface.GetBroadcast (), /*lifetime=*/ Simulator::GetMaximumSimulationTime ());
          m_routingTable.AddRoute (rt);
        }
    }
  else
    {
      NS_LOG_LOGIC ("AODV does not work with more then one address per each interface. Ignore added address");
    }
}

void
RoutingProtocol::NotifyRemoveAddress (uint32_t i, Ipv4InterfaceAddress address)//新しいアドレスがインターフェイスから削除されるたびに通知されるように、プロトコルはこのメソッドを実装することが期待されます。
{
  NS_LOG_FUNCTION (this);
  Ptr<Socket> socket = FindSocketWithInterfaceAddress (address);
  if (socket)
    {
      m_routingTable.DeleteAllRoutesFromInterface (address);
      socket->Close ();
      m_socketAddresses.erase (socket);

      Ptr<Socket> unicastSocket = FindSubnetBroadcastSocketWithInterfaceAddress (address);
      if (unicastSocket)
        {
          unicastSocket->Close ();
          m_socketAddresses.erase (unicastSocket);
        }

      Ptr<Ipv4L3Protocol> l3 = m_ipv4->GetObject<Ipv4L3Protocol> ();
      if (l3->GetNAddresses (i))
        {
          Ipv4InterfaceAddress iface = l3->GetAddress (i, 0);
          // このインターフェイスのみをリッスンするソケットを作成する
          Ptr<Socket> socket = Socket::CreateSocket (GetObject<Node> (),
                                                     UdpSocketFactory::GetTypeId ());
          NS_ASSERT (socket != 0);
          socket->SetRecvCallback (MakeCallback (&RoutingProtocol::RecvAodv, this));
          // ブロードキャストを受信できるように、任意のIPアドレスにバインドする。
          socket->BindToNetDevice (l3->GetNetDevice (i));
          socket->Bind (InetSocketAddress (iface.GetLocal (), AODV_PORT));
          socket->SetAllowBroadcast (true);
          socket->SetIpRecvTtl (true);
          m_socketAddresses.insert (std::make_pair (socket, iface));

          // ユニキャストソケットも作成する
          socket = Socket::CreateSocket (GetObject<Node> (),
                                         UdpSocketFactory::GetTypeId ());
          NS_ASSERT (socket != 0);
          socket->SetRecvCallback (MakeCallback (&RoutingProtocol::RecvAodv, this));
          socket->BindToNetDevice (l3->GetNetDevice (i));
          socket->Bind (InetSocketAddress (iface.GetBroadcast (), AODV_PORT));
          socket->SetAllowBroadcast (true);
          socket->SetIpRecvTtl (true);
          m_socketSubnetBroadcastAddresses.insert (std::make_pair (socket, iface));

          // ルーティングテーブルにローカル・ブロードキャスト・レコードを追加する
          Ptr<NetDevice> dev = m_ipv4->GetNetDevice (m_ipv4->GetInterfaceForAddress (iface.GetLocal ()));
          RoutingTableEntry rt (/*device=*/ dev, /*dst=*/ iface.GetBroadcast (), /*know seqno=*/ true, /*seqno=*/ 0, /*iface=*/ iface,
                                            /*hops=*/ 1, /*next hop=*/ iface.GetBroadcast (), /*lifetime=*/ Simulator::GetMaximumSimulationTime ());
          m_routingTable.AddRoute (rt);
        }
      if (m_socketAddresses.empty ())
        {
          NS_LOG_LOGIC ("No aodv interfaces");
          m_htimer.Cancel ();
          m_nb.Clear ();
          m_routingTable.Clear ();
          return;
        }
    }
  else
    {
      NS_LOG_LOGIC ("Remove address not participating in AODV operation");
    }
}

bool
RoutingProtocol::IsMyOwnAddress (Ipv4Address src) //自身のインターフェースからパケットが送信されていることを確認します。
{
  NS_LOG_FUNCTION (this << src);
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j =
         m_socketAddresses.begin (); j != m_socketAddresses.end (); ++j)
    {
      Ipv4InterfaceAddress iface = j->second;
      if (src == iface.GetLocal ())
        {
          return true;
        }
    }
  return false;
}

Ptr<Ipv4Route>
RoutingProtocol::LoopbackRoute (const Ipv4Header & hdr, Ptr<NetDevice> oif) const
{
  NS_LOG_FUNCTION (this << hdr);
  NS_ASSERT (m_lo != 0);
  Ptr<Ipv4Route> rt = Create<Ipv4Route> ();
  rt->SetDestination (hdr.GetDestination ());
  //
  // ここでのソースアドレスの選択は厄介だ。 
  //ループバック・ルートは、AODVがルートを持っていないときに返される。
  //このため、ルートが見つかるまでの間、
  //パケットはループバックされ、RouteInput()メソッドで処理（キャッシュ）される。
  //しかし、TCPのような接続指向のプロトコルは、
  //エンドポイントの4タプル（src、srcポート、dst、dstポート）を作成し、
  //チェックサムのための擬似ヘッダを作成する必要があります。 
  //そのため、AODVは最終的な送信元アドレス を正しく推測する必要がある。
  //
  // 単一インターフェース、単一アドレスのノードの場合、
  //これは問題ではない。複数の発信インターフェイスが存在する可能性がある場合、
  //ここで実装されているポリシーは、最初に利用可能なAODVインターフェイスを選択することである。
  //RouteOutput()の呼び出し元が発信インタフェースを指定した場合、
  //発信元アドレス の選択がさらに制約される。
  //
  std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j = m_socketAddresses.begin ();
  if (oif)
    {
      // Iterate to find an address on the oif device
      for (j = m_socketAddresses.begin (); j != m_socketAddresses.end (); ++j)
        {
          Ipv4Address addr = j->second.GetLocal ();
          int32_t interface = m_ipv4->GetInterfaceForAddress (addr);
          if (oif == m_ipv4->GetNetDevice (static_cast<uint32_t> (interface)))
            {
              rt->SetSource (addr);
              break;
            }
        }
    }
  else
    {
      rt->SetSource (j->second.GetLocal ());
    }
  NS_ASSERT_MSG (rt->GetSource () != Ipv4Address (), "Valid AODV source address not found");
  rt->SetGateway (Ipv4Address ("127.0.0.1"));
  rt->SetOutputDevice (m_lo);
  return rt;
}

void
RoutingProtocol::SendRequest (Ipv4Address dst) //RREQを送信する
{
  //printf("Send Request\n");
  NS_LOG_FUNCTION ( this << dst);
  // ノードは1秒間にRREQ_RATELIMITを超えるRREQメッセージを発信すべきではない[SHOULD NOT]。
  if (m_rreqCount == m_rreqRateLimit)
    {
      //新しくスケジューリングを行う
      Simulator::Schedule (m_rreqRateLimitTimer.GetDelayLeft () + MicroSeconds (1000),
                           &RoutingProtocol::SendRequest, this, dst);
      return;
    }
  else
    {
      m_rreqCount++;
    }
  // RREQのヘッダを作成
  RreqHeader rreqHeader;
  rreqHeader.SetDst (dst);

  RoutingTableEntry rt;
  // ルーティングテーブルのHopフィールドを使った拡大リングサーチの管理
  uint16_t ttl = m_ttlStart;
  if (m_routingTable.LookupRoute (dst, rt))
    {
      if (rt.GetFlag () != IN_SEARCH)
        {
          ttl = std::min<uint16_t> (rt.GetHop () + m_ttlIncrement, m_netDiameter);
        }
      else
        {
          ttl = rt.GetHop () + m_ttlIncrement;
          if (ttl > m_ttlThreshold)
            {
              ttl = m_netDiameter;
            }
        }
      if (ttl == m_netDiameter)
        {
          rt.IncrementRreqCnt ();
        }
      if (rt.GetValidSeqNo ())
        {
          rreqHeader.SetDstSeqno (rt.GetSeqNo ());
        }
      else
        {
          rreqHeader.SetUnknownSeqno (true);
        }
      rt.SetHop (ttl);
      rt.SetFlag (IN_SEARCH);
      rt.SetLifeTime (m_pathDiscoveryTime);
      m_routingTable.Update (rt);
    }
  else
    {
      rreqHeader.SetUnknownSeqno (true);
      Ptr<NetDevice> dev = 0;
      //ルーティングテーブル追加部分
      RoutingTableEntry newEntry (/*device=*/ dev, /*dst=*/ dst, /*validSeqNo=*/ false, /*seqno=*/ 0,
                                              /*iface=*/ Ipv4InterfaceAddress (),/*hop=*/ ttl,
                                              /*nextHop=*/ Ipv4Address (), /*lifeTime=*/ m_pathDiscoveryTime);
      // Check if TtlStart == NetDiameter
      if (ttl == m_netDiameter)
        {
          newEntry.IncrementRreqCnt ();
        }
      newEntry.SetFlag (IN_SEARCH);
      m_routingTable.AddRoute (newEntry);
    }

  if (m_gratuitousReply)
    {
      rreqHeader.SetGratuitousRrep (true);
    }
  if (m_destinationOnly)
    {
      rreqHeader.SetDestinationOnly (true);
    }

  m_seqNo++;
  rreqHeader.SetOriginSeqno (m_seqNo);
  m_requestId++;
  rreqHeader.SetId (m_requestId);

  // aodvが使用する各インターフェースから、サブネット指向のブロードキャストとしてRREQを送信する。
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j =
         m_socketAddresses.begin (); j != m_socketAddresses.end (); ++j)
    {
      Ptr<Socket> socket = j->first;
      Ipv4InterfaceAddress iface = j->second;

      rreqHeader.SetOrigin (iface.GetLocal ());
      m_rreqIdCache.IsDuplicate (iface.GetLocal (), m_requestId);

      Ptr<Packet> packet = Create<Packet> ();
      SocketIpTtlTag tag;
      tag.SetTtl (ttl);
      packet->AddPacketTag (tag);
      packet->AddHeader (rreqHeader);
      TypeHeader tHeader (AODVTYPE_RREQ);
      packet->AddHeader (tHeader);
      // 32アドレスの場合は全ホストにブロードキャスト送信、それ以外はサブネットに直接送信
      Ipv4Address destination;
      if (iface.GetMask () == Ipv4Mask::GetOnes ())
        {
          destination = Ipv4Address ("255.255.255.255");
        }
      else
        {
          destination = iface.GetBroadcast ();
        }
      NS_LOG_DEBUG ("Send RREQ with id " << rreqHeader.GetId () << " to socket");
      m_lastBcastTime = Simulator::Now ();
      Simulator::Schedule (Time (MilliSeconds (m_uniformRandomVariable->GetInteger (0, 10))), &RoutingProtocol::SendTo, this, socket, packet, destination);
    }
  ScheduleRreqRetry (dst);
}

void
RoutingProtocol::SendTo (Ptr<Socket> socket, Ptr<Packet> packet, Ipv4Address destination)//destinationにパケットを送信
{
  socket->SendTo (packet, 0, InetSocketAddress (destination, AODV_PORT));

}
void
RoutingProtocol::ScheduleRreqRetry (Ipv4Address dst)//RREQの再送信
{
  NS_LOG_FUNCTION (this << dst);
  if (m_addressReqTimer.find (dst) == m_addressReqTimer.end ())
    {
      Timer timer (Timer::CANCEL_ON_DESTROY);
      m_addressReqTimer[dst] = timer;
    }
  m_addressReqTimer[dst].SetFunction (&RoutingProtocol::RouteRequestTimerExpire, this);
  m_addressReqTimer[dst].Remove ();
  m_addressReqTimer[dst].SetArguments (dst);
  RoutingTableEntry rt;
  m_routingTable.LookupRoute (dst, rt);
  Time retry;
  if (rt.GetHop () < m_netDiameter)
    {
      retry = 2 * m_nodeTraversalTime * (rt.GetHop () + m_timeoutBuffer);
    }
  else
    {
      NS_ABORT_MSG_UNLESS (rt.GetRreqCnt () > 0, "Unexpected value for GetRreqCount ()");
      uint16_t backoffFactor = rt.GetRreqCnt () - 1;
      NS_LOG_LOGIC ("Applying binary exponential backoff factor " << backoffFactor);
      retry = m_netTraversalTime * (1 << backoffFactor);
    }
  m_addressReqTimer[dst].Schedule (retry);
  NS_LOG_LOGIC ("Scheduled RREQ retry in " << retry.GetSeconds () << " seconds");
}

void
RoutingProtocol::RecvAodv (Ptr<Socket> socket) //制御パケットを受信して​​処理します。 EERQ受信時の処理？
{
  NS_LOG_FUNCTION (this << socket);
  Address sourceAddress;
  Ptr<Packet> packet = socket->RecvFrom (sourceAddress);
  InetSocketAddress inetSourceAddr = InetSocketAddress::ConvertFrom (sourceAddress);
  Ipv4Address sender = inetSourceAddr.GetIpv4 ();
  Ipv4Address receiver;

  if (m_socketAddresses.find (socket) != m_socketAddresses.end ())
    {
      receiver = m_socketAddresses[socket].GetLocal ();
    }
  else if (m_socketSubnetBroadcastAddresses.find (socket) != m_socketSubnetBroadcastAddresses.end ())
    {
      receiver = m_socketSubnetBroadcastAddresses[socket].GetLocal ();
    }
  else
    {
      NS_ASSERT_MSG (false, "Received a packet from an unknown socket");
    }
  NS_LOG_DEBUG ("AODV node " << this << " received a AODV packet from " << sender << " to " << receiver);

  UpdateRouteToNeighbor (sender, receiver);
  TypeHeader tHeader (AODVTYPE_RREQ);
  packet->RemoveHeader (tHeader);
  if (!tHeader.IsValid ())
    {
      NS_LOG_DEBUG ("AODV message " << packet->GetUid () << " with unknown type received: " << tHeader.Get () << ". Drop");
      return; // drop
    }
  switch (tHeader.Get ())
    {
    case AODVTYPE_RREQ:
      {
        RecvRequest (packet, receiver, sender);
        break;
      }
    case AODVTYPE_RREP:
      {
        RecvReply (packet, receiver, sender);
        break;
      }
    case AODVTYPE_RERR:
      {
        RecvError (packet, sender);
        break;
      }
    case AODVTYPE_RREP_ACK:
      {
        RecvReplyAck (sender);
        break;
      }
    case AODVTYPE_WHC:
      {

        RecvWHC (packet, receiver, sender);
        break;
      }
    case AODVTYPE_WHE:
      {
        RecvWHE (packet, receiver, sender);
        break;
      }
    }
}

bool
RoutingProtocol::UpdateRouteLifeTime (Ipv4Address addr, Time lifetime) //ルーティング テーブル エントリのライフタイム フィールドを、エントリが存在する場合は既存のライフタイムと lt の最大値に設定します。
{
  NS_LOG_FUNCTION (this << addr << lifetime);
  RoutingTableEntry rt;
  if (m_routingTable.LookupRoute (addr, rt))
    {
      if (rt.GetFlag () == VALID)
        {
          NS_LOG_DEBUG ("Updating VALID route");
          rt.SetRreqCnt (0);
          rt.SetLifeTime (std::max (lifetime, rt.GetLifeTime ()));
          m_routingTable.Update (rt);
          return true;
        }
    }
  return false;
}

void
RoutingProtocol::UpdateRouteToNeighbor (Ipv4Address sender, Ipv4Address receiver) //近隣レコードを更新します。
{
  NS_LOG_FUNCTION (this << "sender " << sender << " receiver " << receiver);
  RoutingTableEntry toNeighbor;
  if (!m_routingTable.LookupRoute (sender, toNeighbor))
    {
      Ptr<NetDevice> dev = m_ipv4->GetNetDevice (m_ipv4->GetInterfaceForAddress (receiver));
      RoutingTableEntry newEntry (/*device=*/ dev, /*dst=*/ sender, /*know seqno=*/ false, /*seqno=*/ 0,
                                              /*iface=*/ m_ipv4->GetAddress (m_ipv4->GetInterfaceForAddress (receiver), 0),
                                              /*hops=*/ 1, /*next hop=*/ sender, /*lifetime=*/ m_activeRouteTimeout);
      m_routingTable.AddRoute (newEntry);
    }
  else
    {
      Ptr<NetDevice> dev = m_ipv4->GetNetDevice (m_ipv4->GetInterfaceForAddress (receiver));
      if (toNeighbor.GetValidSeqNo () && (toNeighbor.GetHop () == 1) && (toNeighbor.GetOutputDevice () == dev))
        {
          toNeighbor.SetLifeTime (std::max (m_activeRouteTimeout, toNeighbor.GetLifeTime ()));
        }
      else
        {
          RoutingTableEntry newEntry (/*device=*/ dev, /*dst=*/ sender, /*know seqno=*/ false, /*seqno=*/ 0,
                                                  /*iface=*/ m_ipv4->GetAddress (m_ipv4->GetInterfaceForAddress (receiver), 0),
                                                  /*hops=*/ 1, /*next hop=*/ sender, /*lifetime=*/ std::max (m_activeRouteTimeout, toNeighbor.GetLifeTime ()));
          m_routingTable.Update (newEntry);
        }
    }

}

void
RoutingProtocol::RecvRequest (Ptr<Packet> p, Ipv4Address receiver, Ipv4Address src) //RREQを受信
{
  //printf("Receav RREQ\n");
  NS_LOG_FUNCTION (this);
  RreqHeader rreqHeader;
  p->RemoveHeader (rreqHeader);

  // ノードは、ブラックリストにあるノードから受信したすべてのRREQを無視する。
  RoutingTableEntry toPrev;
  if (m_routingTable.LookupRoute (src, toPrev))
    {
      if (toPrev.IsUnidirectional ())
        {
          NS_LOG_DEBUG ("Ignoring RREQ from node in blacklist");
          return;
        }
    }

  uint32_t id = rreqHeader.GetId ();
  Ipv4Address origin = rreqHeader.GetOrigin ();

  /*
   *  ノードは同じOriginator IP AddressとRREQ IDを持つRREQを受信したかどうかをチェックする。
   *  そのようなRREQを受信した場合、ノードは新たに受信したRREQを黙って破棄する。
   */
  if (m_rreqIdCache.IsDuplicate (origin, id))
    {
      NS_LOG_DEBUG ("Ignoring RREQ due to duplicate");
      return;
    }

  //　RREQホップ数の増加
  uint8_t hop = rreqHeader.GetHopCount () + 1;
  rreqHeader.SetHopCount (hop);

  /*
   *  逆ルートが作成または更新されると、ルートに対する以下のアクションも実行される：
   *  1. RREQの発信元シーケンス番号とルートテーブルエントリーの対応する宛先シーケンス番号が比較され、
   * 　　既存の値より大きければコピーされる。
   *  2. 有効なシーケンス番号フィールドがtrueに設定される；
   *  3. ルーティングテーブルの次のホップはRREQを受信したノードになる
   *  4. ホップ数はRREQメッセージのホップ数からコピーされる；
   *  5. ここで、MinimalLifetime = 現在時刻 + 2*NetTraversalTime - 2*HopCount*NodeTraversalTime である。
   */
  RoutingTableEntry toOrigin;
  if (!m_routingTable.LookupRoute (origin, toOrigin)) //宛先アドレス dst を使用してルーティング テーブル エントリを検索します。
    {
      Ptr<NetDevice> dev = m_ipv4->GetNetDevice (m_ipv4->GetInterfaceForAddress (receiver));
      RoutingTableEntry newEntry (/*device=*/ dev, /*dst=*/ origin, /*validSeno=*/ true, /*seqNo=*/ rreqHeader.GetOriginSeqno (),
                                              /*iface=*/ m_ipv4->GetAddress (m_ipv4->GetInterfaceForAddress (receiver), 0), /*hops=*/ hop,
                                              /*nextHop*/ src, /*timeLife=*/ Time ((2 * m_netTraversalTime - 2 * hop * m_nodeTraversalTime)));
      m_routingTable.AddRoute (newEntry);
    }
  else
    {
      if (toOrigin.GetValidSeqNo ())
        {
          if (int32_t (rreqHeader.GetOriginSeqno ()) - int32_t (toOrigin.GetSeqNo ()) > 0)
            {
              toOrigin.SetSeqNo (rreqHeader.GetOriginSeqno ());
            }
        }
      else
        {
          toOrigin.SetSeqNo (rreqHeader.GetOriginSeqno ());
        }
      toOrigin.SetValidSeqNo (true);
      toOrigin.SetNextHop (src);
      toOrigin.SetOutputDevice (m_ipv4->GetNetDevice (m_ipv4->GetInterfaceForAddress (receiver)));
      toOrigin.SetInterface (m_ipv4->GetAddress (m_ipv4->GetInterfaceForAddress (receiver), 0));
      toOrigin.SetHop (hop);
      toOrigin.SetLifeTime (std::max (Time (2 * m_netTraversalTime - 2 * hop * m_nodeTraversalTime),
                                      toOrigin.GetLifeTime ()));
      m_routingTable.Update (toOrigin);
      //m_nb.Update (src, Time (AllowedHelloLoss * HelloInterval));
    }


  RoutingTableEntry toNeighbor;
  if (!m_routingTable.LookupRoute (src, toNeighbor))
    {
      NS_LOG_DEBUG ("Neighbor:" << src << " not found in routing table. Creating an entry");
      Ptr<NetDevice> dev = m_ipv4->GetNetDevice (m_ipv4->GetInterfaceForAddress (receiver));
      RoutingTableEntry newEntry (dev, src, false, rreqHeader.GetOriginSeqno (),
                                  m_ipv4->GetAddress (m_ipv4->GetInterfaceForAddress (receiver), 0),
                                  1, src, m_activeRouteTimeout);
      m_routingTable.AddRoute (newEntry);
    }
  else
    {
      toNeighbor.SetLifeTime (m_activeRouteTimeout);
      toNeighbor.SetValidSeqNo (false);
      toNeighbor.SetSeqNo (rreqHeader.GetOriginSeqno ());
      toNeighbor.SetFlag (VALID);
      toNeighbor.SetOutputDevice (m_ipv4->GetNetDevice (m_ipv4->GetInterfaceForAddress (receiver)));
      toNeighbor.SetInterface (m_ipv4->GetAddress (m_ipv4->GetInterfaceForAddress (receiver), 0));
      toNeighbor.SetHop (1);
      toNeighbor.SetNextHop (src);
      m_routingTable.Update (toNeighbor);
    }
  m_nb.Update (src, Time (m_allowedHelloLoss * m_helloInterval));

  NS_LOG_LOGIC (receiver << " receive RREQ with hop count " << static_cast<uint32_t> (rreqHeader.GetHopCount ())
                         << " ID " << rreqHeader.GetId ()
                         << " to destination " << rreqHeader.GetDst ());

  //  ノードは以下のどちらかの場合にRREPを生成する：
  //  (i) それ自身が目的地である、
  if (IsMyOwnAddress (rreqHeader.GetDst ()))
    {
      printf("RREQが目的地に到着\n");
      m_routingTable.LookupRoute (origin, toOrigin);
      NS_LOG_DEBUG ("Send reply since I am the destination");
      SendReply (rreqHeader, toOrigin);
      return;
    }
  /*
   * (ii)または、宛先へのアクティブなルートがあり、
   　ノードの既存の宛先のルートテーブルエントリーの宛先シーケンス番号が有効で、
   　RREQの宛先シーケンス番号以上であり、「宛先のみ」フラグが設定されていない。
   */
   RoutingTableEntry toDst;
   Ipv4Address dst = rreqHeader.GetDst ();
  if (m_routingTable.LookupRoute (dst, toDst))
    {
      /*
       * RREQをドロップすると、このノードのRREPはループする。
       */
      if (toDst.GetNextHop () == src)
        {
          NS_LOG_DEBUG ("Drop RREQ from " << src << ", dest next hop " << toDst.GetNextHop ());
          return;
        }
      /*
       * 要求された宛先の宛先シーケンス番号は、RREQメッセージで受信した対応する値と、
       　要求された宛先のノードが現在保持している宛先シーケンス値の最大値に 設定される。
　　　　 ただし、転送ノードは、受信したRREQメッセージで受信した宛先シークエンス番号の値が
　　　　 以下の値であっても、そのノードが保持している宛先シーケンス番号の値を変更してはならない[MUST NOT]。
         受信RREQで受信した値が、転送ノードが現在保持している値よりも大きい場合であっても、
         転送ノードは宛先シーケンス番号の保持値を変更してはならない。
       */
      if ((rreqHeader.GetUnknownSeqno () || (int32_t (toDst.GetSeqNo ()) - int32_t (rreqHeader.GetDstSeqno ()) >= 0))
          && toDst.GetValidSeqNo () )
        {
          // if (!rreqHeader.GetDestinationOnly () && toDst.GetFlag () == VALID)
          //   {
          //     m_routingTable.LookupRoute (origin, toOrigin);
          //     SendReplyByIntermediateNode (toDst, toOrigin, rreqHeader.GetGratuitousRrep ());
          //     return;
          //   }
          rreqHeader.SetDstSeqno (toDst.GetSeqNo ());
          rreqHeader.SetUnknownSeqno (false);
        }
    }

  SocketIpTtlTag tag;
  p->RemovePacketTag (tag);
  if (tag.GetTtl () < 2)
    {
      NS_LOG_DEBUG ("TTL exceeded. Drop RREQ origin " << src << " destination " << dst );
      return;
    }

  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j =
         m_socketAddresses.begin (); j != m_socketAddresses.end (); ++j)
    {
      Ptr<Socket> socket = j->first;
      Ipv4InterfaceAddress iface = j->second;
      Ptr<Packet> packet = Create<Packet> ();
      SocketIpTtlTag ttl;
      ttl.SetTtl (tag.GetTtl () - 1);
      packet->AddPacketTag (ttl);
      packet->AddHeader (rreqHeader);
      TypeHeader tHeader (AODVTYPE_RREQ);
      packet->AddHeader (tHeader);
      // 32アドレスの場合は全ホストにブロードキャスト送信、それ以外はサブネットに直接送信
      Ipv4Address destination;
      if (iface.GetMask () == Ipv4Mask::GetOnes ())
        {
          destination = Ipv4Address ("255.255.255.255");
        }
      else
        {
          destination = iface.GetBroadcast ();
        }
      m_lastBcastTime = Simulator::Now ();
      Simulator::Schedule (Time (MilliSeconds (m_uniformRandomVariable->GetInteger (0, 10))), &RoutingProtocol::SendTo, this, socket, packet, destination);

    }
}

/// @brief 
/// @param rreqHeader 
/// @param toOrigin 
void
RoutingProtocol::SendReply (RreqHeader const & rreqHeader, RoutingTableEntry const & toOrigin)//RREPを送信
{

  //printf("Send Reply\n");
  NS_LOG_FUNCTION (this << toOrigin.GetDestination ());
  /*
   * 宛先ノードは、RREQパケットのシーケンス番号がインクリメントされた値と等しい場合、
     自身のシーケンス番号を1つインクリメントしなければならない[MUST]。
     そうでない場合、宛先はRREPメッセージを生成する前にシーケンス番号を変更しない。
   */

  //隣接ノードリスト取得
  std::vector<Ipv4Address> List = m_nb.GetNeighborList();

  //printf("隣接リスト表示\n");

  int size = List.size();

  // 隣接リスト表示
  // for(int i = 0; i < size;i++ )
  // {
  //   //auto neighbor = List.at(i);

  //   ///printf("%u\n",neighbor.Get());
  // }

 // printf("send時 size:%d\n",size);


  if (!rreqHeader.GetUnknownSeqno () && (rreqHeader.GetDstSeqno () == m_seqNo + 1))
    {
      m_seqNo++;
    }

  rrepid++;

  RrepHeader rrepHeader ( /*prefixSize=*/ 0, /*hops=*/ 0, /*dst=*/ rreqHeader.GetDst (),
                                          /*dstSeqNo=*/ m_seqNo, /*origin=*/ toOrigin.GetDestination (), /*lifeTime=*/ m_myRouteTimeout,
                          /*隣接ノードリスト*/List, size, /*id=*/rrepid);

  printf("RREPを送信　　ID：%d\n", rrepHeader.Getid());

 //printf("RREPのネクストホップ：%u\n", toOrigin.GetNextHop().Get());

  if(toOrigin.GetNextHop() == Ipv4Address("10.0.0.3"))
  {
    printf("ネクストホップがWHの可能性があります\n");
  }

  rrepHeader.SetNeighbors(List);

  //パケット作成部分？
  //printf("パケット\n");
  std::vector<Ipv4Address> test = rrepHeader.GetNeighbors();
  for(int i = 0; i < size;i++ )
  {
    //auto neighbor = test.at(i);

    //printf("%u\n",neighbor.Get());
  }


  Ptr<Packet> packet = Create<Packet> ();
  SocketIpTtlTag tag;
  tag.SetTtl (toOrigin.GetHop ());
  packet->AddPacketTag (tag);
  packet->AddHeader (rrepHeader);
  TypeHeader tHeader (AODVTYPE_RREP);
  packet->AddHeader (tHeader);
  Ptr<Socket> socket = FindSocketWithInterfaceAddress (toOrigin.GetInterface ());
  NS_ASSERT (socket);
  socket->SendTo (packet, 0, InetSocketAddress (toOrigin.GetNextHop (), AODV_PORT));
}

//中間ノードでRREPを送信
// void
// RoutingProtocol::SendReplyByIntermediateNode (RoutingTableEntry & toDst, RoutingTableEntry & toOrigin, bool gratRep)
// {
//   NS_LOG_FUNCTION (this);
//   RrepHeader rrepHeader (/*prefix size=*/ 0, /*hops=*/ toDst.GetHop (), /*dst=*/ toDst.GetDestination (), /*dst seqno=*/ toDst.GetSeqNo (),
//                                           /*origin=*/ toOrigin.GetDestination (), /*lifetime=*/ toDst.GetLifeTime ());
//   /* RREQを受信したノードが隣接ノードであった場合、我々は次のようになる。
//   　おそらく一方向リンクに直面している...。RREP-ackをリクエストする
//    */
//   if (toDst.GetHop () == 1)
//     {
//       rrepHeader.SetAckRequired (true);
//       RoutingTableEntry toNextHop;
//       m_routingTable.LookupRoute (toOrigin.GetNextHop (), toNextHop);
//       toNextHop.m_ackTimer.SetFunction (&RoutingProtocol::AckTimerExpire, this);
//       toNextHop.m_ackTimer.SetArguments (toNextHop.GetDestination (), m_blackListTimeout);
//       toNextHop.m_ackTimer.SetDelay (m_nextHopWait);
//     }
//   toDst.InsertPrecursor (toOrigin.GetNextHop ());
//   toOrigin.InsertPrecursor (toDst.GetNextHop ());
//   m_routingTable.Update (toDst);
//   m_routingTable.Update (toOrigin);

//   Ptr<Packet> packet = Create<Packet> ();
//   SocketIpTtlTag tag;
//   tag.SetTtl (toOrigin.GetHop ());
//   packet->AddPacketTag (tag);
//   packet->AddHeader (rrepHeader);
//   TypeHeader tHeader (AODVTYPE_RREP);
//   packet->AddHeader (tHeader);
//   Ptr<Socket> socket = FindSocketWithInterfaceAddress (toOrigin.GetInterface ());
//   NS_ASSERT (socket);
//   socket->SendTo (packet, 0, InetSocketAddress (toOrigin.GetNextHop (), AODV_PORT));

//   // 無償RREPの生成
//   if (gratRep)
//     {
//       RrepHeader gratRepHeader (/*prefix size=*/ 0, /*hops=*/ toOrigin.GetHop (), /*dst=*/ toOrigin.GetDestination (),
//                                                  /*dst seqno=*/ toOrigin.GetSeqNo (), /*origin=*/ toDst.GetDestination (),
//                                                  /*lifetime=*/ toOrigin.GetLifeTime ());
//       Ptr<Packet> packetToDst = Create<Packet> ();
//       SocketIpTtlTag gratTag;
//       gratTag.SetTtl (toDst.GetHop ());
//       packetToDst->AddPacketTag (gratTag);
//       packetToDst->AddHeader (gratRepHeader);
//       TypeHeader type (AODVTYPE_RREP);
//       packetToDst->AddHeader (type);
//       Ptr<Socket> socket = FindSocketWithInterfaceAddress (toDst.GetInterface ());
//       NS_ASSERT (socket);
//       NS_LOG_LOGIC ("Send gratuitous RREP " << packet->GetUid ());
//       socket->SendTo (packetToDst, 0, InetSocketAddress (toDst.GetNextHop (), AODV_PORT));
//     }
// }

void
RoutingProtocol::SendReplyAck (Ipv4Address neighbor) //RREP_ACKを送信します。
{
  NS_LOG_FUNCTION (this << " to " << neighbor);
  RrepAckHeader h;
  TypeHeader typeHeader (AODVTYPE_RREP_ACK);
  Ptr<Packet> packet = Create<Packet> ();
  SocketIpTtlTag tag;
  tag.SetTtl (1);
  packet->AddPacketTag (tag);
  packet->AddHeader (h);
  packet->AddHeader (typeHeader);
  RoutingTableEntry toNeighbor;
  m_routingTable.LookupRoute (neighbor, toNeighbor);
  Ptr<Socket> socket = FindSocketWithInterfaceAddress (toNeighbor.GetInterface ());
  NS_ASSERT (socket);
  socket->SendTo (packet, 0, InetSocketAddress (neighbor, AODV_PORT));
}

void
RoutingProtocol::RecvReply (Ptr<Packet> p, Ipv4Address receiver, Ipv4Address sender) //RREPを受信
{
  NS_LOG_FUNCTION (this << " src " << sender);

  

  RrepHeader rrepHeader;
  p->RemoveHeader (rrepHeader);

  if(IsMyOwnAddress (rrepHeader.GetOrigin ()))
  {
    printf("RREPが目的地に到着---------------------------------ID:%d\n", rrepHeader.Getid());

    RouteRequestTimerExpire(Ipv4Address("10.0.0.200"));

    // exit(0);
    return;
  }

  Ipv4Address dst = rrepHeader.GetDst ();
  NS_LOG_LOGIC ("RREP destination " << dst << " RREP origin " << rrepHeader.GetOrigin ());

  uint8_t hop = rrepHeader.GetHopCount () + 1;
  rrepHeader.SetHopCount (hop);

  // RREPがHelloメッセージの場合
  if (dst == rrepHeader.GetOrigin ())
    {
      ProcessHello (rrepHeader, receiver);
      return;
    }

  printf("RREPを受信　　ID：%d\n", rrepHeader.Getid());

    std::ofstream writing_file;
    std::string filename = "com_num.txt";
    writing_file.open(filename, std::ios::app);
    std::string writing_text ="1";
    writing_file << writing_text << std::endl;
    writing_file.close();

  //printf("RREPのreceiver: %d\n", receiver.Get());

  if(receiver == Ipv4Address("10.1.2.1"))
  {
    printf("WHノードの可能性があります\n");

    std::ofstream writing_file;
    std::string filename = "WH_count.txt";
    writing_file.open(filename, std::ios::app);
    std::string writing_text ="1";
    writing_file << writing_text << std::endl;
    writing_file.close();
  }

    //printf("Recv Reply  IP:%u\n", receiver.Get());

    //printf("受け取った隣接ノード情報\n");
    std::vector<Ipv4Address> get_List = rrepHeader.GetNeighbors ();

    int get_size = rrepHeader.Getsize();

    int data_size = 4*get_size;

    std::ofstream writing_file2;
  std::string filename2 = "sample.txt";
  writing_file2.open(filename2, std::ios::app);
  // std::string writing_text = "";
  writing_file2 << data_size << std::endl;
  writing_file2.close(); 
  //printf("get size:%d\n",get_size);
  //Ipv4Address test1 = get_List[0];
  //Ipv4Address test = get_List[1];
  //printf("get_List[0]:%u\n", test1.Get());
  //printf("get_List[1]:%u\n", test.Get());
    //隣接リスト表示
  // for(int i = 0; i < get_size; i++ )
  // {
  //   //printf("i:%d\n", i);
  //   //auto neighbor = get_List.at(i);
  //   //printf("%u\n",neighbor.Get());
  // }

  
  //隣接ノードリスト取得
  std::vector<Ipv4Address> List = m_nb.GetNeighborList();

  //printf("隣接リスト表示\n");

  int my_size = List.size();

  //隣接リスト表示
  for(int i = 0; i <my_size;i++ )
  {
    //auto neighbor = List.at(i);

    //printf("%u\n",neighbor.Get());
  }

  
  /*
   * 宛先へのルートテーブルエントリーが作成または更新された場合、以下のアクションが発生する：
   * -  ルートはアクティブとしてマークされる、
   * -  宛先シーケンス番号が有効であるとマークされる、
   * -  ルートエントリーのネクストホップは、RREPを受信したノードに割り当てられる、 これはIPヘッダーの送信元IPアドレスフィールドで示される、
   * -  ホップ数はRREPメッセージのホップ数＋1に設定される。
   * -  有効期限は現在時刻にRREPメッセージのLifetimeの値を加えたものに設定される、
   * -  宛先シーケンス番号はRREPメッセージの宛先シーケンス番号である。
   */
  Ptr<NetDevice> dev = m_ipv4->GetNetDevice (m_ipv4->GetInterfaceForAddress (receiver));
  RoutingTableEntry newEntry (/*device=*/ dev, /*dst=*/ dst, /*validSeqNo=*/ true, /*seqno=*/ rrepHeader.GetDstSeqno (),
                                          /*iface=*/ m_ipv4->GetAddress (m_ipv4->GetInterfaceForAddress (receiver), 0),/*hop=*/ hop,
                                          /*nextHop=*/ sender, /*lifeTime=*/ rrepHeader.GetLifeTime ());
  RoutingTableEntry toDst;
  if (m_routingTable.LookupRoute (dst, toDst))
    {
      /*
       * 既存のエントリーは、以下の場合にのみ更新される：
       * (i) ルーティングテーブルのシーケンス番号が、ルートテーブルエントリーに無効とマークされている。
       */
      if (!toDst.GetValidSeqNo ())
        {
          m_routingTable.Update (newEntry);
        }
      // (ii)RREPの宛先シーケンス番号が、ノードのコピーした宛先シーケンス番号より大きく、既知の値が有効である、
      else if ((int32_t (rrepHeader.GetDstSeqno ()) - int32_t (toDst.GetSeqNo ())) > 0)
        {
          m_routingTable.Update (newEntry);
        }
      else
        {
          // (iii) シーケンス番号は同じだが、ルートが非アクティブとマークされている。
          if ((rrepHeader.GetDstSeqno () == toDst.GetSeqNo ()) && (toDst.GetFlag () != VALID))
            {
              m_routingTable.Update (newEntry);
            }
          // (iv) シーケンス番号が同じで、新ホップカウントがルートテーブルエントリーのホップカウントより小さい。
          else if ((rrepHeader.GetDstSeqno () == toDst.GetSeqNo ()) && (hop < toDst.GetHop ()))
            {
              m_routingTable.Update (newEntry);
            }
        }
    }
  else
    {
      // この宛先の転送ルートがまだ存在しない場合は作成される。
      NS_LOG_LOGIC ("add new route");
      m_routingTable.AddRoute (newEntry);
    }
  // RREP-ACKメッセージを返送することにより、RREPの受信を確認する。
  if (rrepHeader.GetAckRequired ())
    {
      SendReplyAck (sender);
      rrepHeader.SetAckRequired (false);
    }
  NS_LOG_LOGIC ("receiver " << receiver << " origin " << rrepHeader.GetOrigin ());
  //RREPが目的地に到着
  if (IsMyOwnAddress (rrepHeader.GetOrigin ()))
    {
      get_rreptimes++;

      printf("RREPが目的地に到着   ID:%d\n", rrepHeader.Getid());

      
      // if (toDst.GetFlag () == IN_SEARCH)
      //   {
      //     m_routingTable.Update (newEntry);
      //     m_addressReqTimer[dst].Remove ();
      //     m_addressReqTimer.erase (dst);
      //   }
      m_routingTable.LookupRoute (dst, toDst);
      SendRequest(Ipv4Address("10.0.0.200"));
      //SendPacketFromQueue (dst, toDst.GetRoute ());
      
      // if(get_rreptimes == 10)
      // {
      //   printf("RREPが10回目的地に到着したため終了\n");

        // exit(0);
      // }

      return;
    }

  RoutingTableEntry toOrigin;
  if (!m_routingTable.LookupRoute (rrepHeader.GetOrigin (), toOrigin) || toOrigin.GetFlag () == IN_SEARCH)
    {
      return; // Impossible! drop.
    }
  toOrigin.SetLifeTime (std::max (m_activeRouteTimeout, toOrigin.GetLifeTime ()));
  m_routingTable.Update (toOrigin);

  // 前駆物質(precursors)に関する最新情報mysss
  if (m_routingTable.LookupValidRoute (rrepHeader.GetDst (), toDst))
    {
      toDst.InsertPrecursor (toOrigin.GetNextHop ());
      m_routingTable.Update (toDst);

      RoutingTableEntry toNextHopToDst;
      m_routingTable.LookupRoute (toDst.GetNextHop (), toNextHopToDst);
      toNextHopToDst.InsertPrecursor (toOrigin.GetNextHop ());
      m_routingTable.Update (toNextHopToDst);

      toOrigin.InsertPrecursor (toDst.GetNextHop ());
      m_routingTable.Update (toOrigin);

      RoutingTableEntry toNextHopToOrigin;
      m_routingTable.LookupRoute (toOrigin.GetNextHop (), toNextHopToOrigin);
      toNextHopToOrigin.InsertPrecursor (toDst.GetNextHop ());
      m_routingTable.Update (toNextHopToOrigin);
    }
  SocketIpTtlTag tag;
  p->RemovePacketTag (tag);
  if (tag.GetTtl () < 2)
    {
      NS_LOG_DEBUG ("TTL exceeded. Drop RREP destination " << dst << " origin " << rrepHeader.GetOrigin ());
      return;
    }

  //RREP送信元から送信された情報を取得
  struct recv_Rrep new_List
  {
    rrepHeader,
    sender
  };

  int size_l = Rrep_List.size();

  //printf("RREP送信元の隣接ノードリストのサイズ:%d\n", size_l);

  //隣接ノードリストに同じシーケンス番号存在しているか確認
  for(int i = 0; i < size_l;i++)
  {
    RrepHeader get_Rrep = Rrep_List.at(i).rrepHeader;
    uint32_t get_id = get_Rrep.GetDstSeqno();
    if(get_id == rrepHeader.GetDstSeqno())
    {
      //printf("シーケンス番号が一致\n");
      Rrep_List.at(i).rrepHeader = rrepHeader;
      break;
    }
    else if(i == size_l -1)
    {
      //printf("新しいオブジェクト挿入\n");
      Rrep_List.push_back(new_List);
    }

  }

  if(size_l == 0){
    //printf("size_l = 0\n");
    Rrep_List.push_back(new_List);
  }

  printf("ネクストホップ：%u\n", toOrigin.GetNextHop().Get());

  


  //隣接ノードリスト比較　自分の隣接ノードリスト：List　受信した隣接ノードリスト：get_List

  for(int i = 0; i < my_size; i++)
  {
    for(int j = 0; j < get_size; j++)
    {
      if(List.at(i) == get_List.at(j))
      {
        printf("同じ隣接ノードが存在  ID:%d\n", rrepHeader.Getid());
        //printf("共通の隣接ノード%u\n", List.at(i).Get());

        rrepHeader.SetNeighbors(List);
        rrepHeader.Setsize(my_size);

        //RREPパケット作製
        Ptr<Packet> packet = Create<Packet> ();
        SocketIpTtlTag ttl;
        ttl.SetTtl (tag.GetTtl () - 1);
        packet->AddPacketTag (ttl);
        packet->AddHeader (rrepHeader);
        TypeHeader tHeader (AODVTYPE_RREP);

        packet->AddHeader (tHeader);
        Ptr<Socket> socket = FindSocketWithInterfaceAddress (toOrigin.GetInterface ());
        NS_ASSERT (socket);
        socket->SendTo (packet, 0, InetSocketAddress (toOrigin.GetNextHop (), AODV_PORT));



        return;
      }
    }
  }

  printf("Send WHC  ID:%d\n", rrepHeader.Getid());
  SendWHC(rrepHeader.Getid());



  // Ptr<Packet> packet = Create<Packet> ();
  // SocketIpTtlTag ttl;
  // ttl.SetTtl (tag.GetTtl () - 1);
  // packet->AddPacketTag (ttl);
  // packet->AddHeader (rrepHeader);
  // TypeHeader tHeader (AODVTYPE_RREP);
  // packet->AddHeader (tHeader);
  // Ptr<Socket> socket = FindSocketWithInterfaceAddress (toOrigin.GetInterface ());
  // NS_ASSERT (socket);
  // socket->SendTo (packet, 0, InetSocketAddress (toOrigin.GetNextHop (), AODV_PORT));
}

void 
RoutingProtocol::SendWHC (uint32_t DstSeqno)
{
  //WHCHeader作製
  printf("WHC送信\n");
  //printf("DstSeqNo2: %d\n", DstSeqno);


  //WHCメッセージパケット作製
  // Ptr<Packet> packet = Create<Packet> ();
  // SocketIpTtlTag ttl;
  // ttl.SetTtl (tag.GetTtl () - 1);
  // packet->AddPacketTag (ttl);
  // packet->AddHeader (WHCHeader);
  // TypeHeader tHeader (AODVTYPE_WHC);
  // packet->AddHeader (tHeader);
  // Ptr<Socket> socket = FindSocketWithInterfaceAddress (toOrigin.GetInterface ());
  // NS_ASSERT (socket);
  // socket->SendTo (packet, 0, InetSocketAddress (toOrigin.GetNextHop (), AODV_PORT));

  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j = m_socketAddresses.begin (); j != m_socketAddresses.end (); ++j)
    {
      Ptr<Socket> socket = j->first;
      Ipv4InterfaceAddress iface = j->second;
      NS_ASSERT (socket);

      WHCHeader h(DstSeqno);
      TypeHeader typeHeader (AODVTYPE_WHC);
      Ptr<Packet> packet = Create<Packet> ();
      SocketIpTtlTag tag;
      tag.SetTtl (1);
      packet->AddPacketTag (tag);
      packet->AddHeader (h);
      packet->AddHeader (typeHeader);
      NS_ASSERT (socket);
     
      // 32アドレスの場合は全ホストにブロードキャスト送信、それ以外はサブネットに直接送信
      Ipv4Address destination;
      if (iface.GetMask () == Ipv4Mask::GetOnes ())
        {
          destination = Ipv4Address ("255.255.255.255");
        }
      else
        {
          destination = iface.GetBroadcast ();
        }
      // Time jitter = Time (MilliSeconds (m_uniformRandomVariable->GetInteger (0, 10)));
      // Simulator::Schedule (jitter, &RoutingProtocol::SendTo, this, socket, packet, destination);
      socket->SendTo (packet->Copy (), 0, InetSocketAddress (destination, AODV_PORT));

      //printf("送信完了\n");
    }

  

  // m_routingTable.LookupRoute (neighbor, toNeighbor);
  // Ptr<Socket> socket = FindSocketWitInterfaceAddress (toNeighbor.GetInterface ());
  // NS_ASSERT (socket);
}

void RoutingProtocol::RecvWHC (Ptr<Packet> p, Ipv4Address receiver, Ipv4Address src)
{
  //printf("WHC受信\n");
  WHCHeader WHCHeader;
  p->RemoveHeader (WHCHeader);

  std::ofstream writing_file;
  std::string filename = "sample.txt";
  writing_file.open(filename, std::ios::app);
  std::string writing_text = "4";
  writing_file << writing_text << std::endl;
  writing_file.close();

  // ノードは、ブラックリストにあるノードから受信したすべてのRREQを無視する。
  RoutingTableEntry toPrev;
  if (m_routingTable.LookupRoute (src, toPrev))
    {
      if (toPrev.IsUnidirectional ())
        {
          NS_LOG_DEBUG ("Ignoring RREQ from node in blacklist");
          return;
        }
    }
  
  //送信元とのルーティングテーブル作製
  RoutingTableEntry toNeighbor;
  if (!m_routingTable.LookupRoute (src, toNeighbor))
    {
      NS_LOG_DEBUG ("Neighbor:" << src << " not found in routing table. Creating an entry");
      Ptr<NetDevice> dev = m_ipv4->GetNetDevice (m_ipv4->GetInterfaceForAddress (receiver));
      RoutingTableEntry newEntry (dev, src, false, WHCHeader.GetDstSeqno (),
                                  m_ipv4->GetAddress (m_ipv4->GetInterfaceForAddress (receiver), 0),
                                  1, src, m_activeRouteTimeout);
      m_routingTable.AddRoute (newEntry);
    }
  else
    {
      toNeighbor.SetLifeTime (m_activeRouteTimeout);
      toNeighbor.SetValidSeqNo (false);
      toNeighbor.SetSeqNo (WHCHeader.GetDstSeqno ());
      toNeighbor.SetFlag (VALID);
      toNeighbor.SetOutputDevice (m_ipv4->GetNetDevice (m_ipv4->GetInterfaceForAddress (receiver)));
      toNeighbor.SetInterface (m_ipv4->GetAddress (m_ipv4->GetInterfaceForAddress (receiver), 0));
      toNeighbor.SetHop (1);
      toNeighbor.SetNextHop (src);
      m_routingTable.Update (toNeighbor);
    }
  m_nb.Update (src, Time (m_allowedHelloLoss * m_helloInterval));

  SendWHE(WHCHeader, toNeighbor);


}

void RoutingProtocol::SendWHE (WHCHeader const & WHCHeader, RoutingTableEntry const & toNeighbor)
{
  NS_LOG_FUNCTION (this << toNeighbor.GetDestination());
  
//隣接ノードリスト取得
  std::vector<Ipv4Address> List = m_nb.GetNeighborList();

  //printf("WHC時隣接リスト取得\n");

  int my_size = List.size();

  //隣接リスト表示
  for(int i = 0; i <my_size;i++ )
  {
    //auto neighbor = List.at(i);

    //printf("%u\n",neighbor.Get());
  }

  uint32_t seq = WHCHeader.GetDstSeqno();

  // printf("SendWHE  ID:%d\n", seq);
  
  WHEHeader WHEHeader (/*dstSeqNo=*/seq, List, my_size);

  //パケット作製
  Ptr<Packet> packet = Create<Packet> ();
  SocketIpTtlTag tag;
  tag.SetTtl (1);
  packet->AddPacketTag (tag);
  packet->AddHeader (WHEHeader);
  TypeHeader tHeader (AODVTYPE_WHE);
  packet->AddHeader (tHeader);
  Ptr<Socket> socket = FindSocketWithInterfaceAddress (toNeighbor.GetInterface ());
  NS_ASSERT (socket);
  socket->SendTo (packet, 0, InetSocketAddress (toNeighbor.GetNextHop (), AODV_PORT));
}


void RoutingProtocol::RecvWHE (Ptr<Packet> p, Ipv4Address receiver, Ipv4Address sender)
{ 
  NS_LOG_FUNCTION (this << " src " << sender);
  //printf("RecvWHE\n");
  //printf("WHEのレシーバー%u\n", receiver.Get());

  if(receiver == Ipv4Address("10.1.2.1") || receiver == Ipv4Address("10.0.0.2"))
  {
    printf("WHノードがWHEメッセージを受信\n");
  }

  // std::ofstream writing_file;
  // std::string filename = "sample.txt";
  // writing_file.open(filename, std::ios::app);
  // std::string writing_text = "1";
  // writing_file << writing_text << std::endl;
  // writing_file.close();
  
  WHEHeader WHEHeader;
  p->RemoveHeader (WHEHeader);

  //  WHEメッセージのシーケンス番号取得
  uint32_t id_WH = WHEHeader.Getid ();

  //rrepから送信された隣接ノードリストに同じシーケンス番号のものが含まれているか調べる
  int List_size = Rrep_List.size();

  struct recv_Rrep new_rrep;
  RrepHeader rrepHeader;

  uint32_t get_id = 0;

  for(int i = 0; i < List_size; i++)
  {
    new_rrep = Rrep_List.at(i);
    rrepHeader = new_rrep.rrepHeader;
    get_id = rrepHeader.Getid();
    if(id_WH == get_id)
    {
      //printf("同一のシーケンス番号を発見\n");
      // sender_neighbors = rrepHeader.GetNeighbors();
      break;
    }
  }

  if(new_rrep.sender == sender){
    NS_LOG_FUNCTION ("RREPの送信元から送信されたIP:"<<sender);
    //printf("RREPの送信元から送信された\n");
    return;
  }
  //rrepから送信されたList取得
  std::vector<Ipv4Address> sender_neighbors = rrepHeader.GetNeighbors();


  //パケット内の隣接ノードリストを取得
  std::vector<Ipv4Address> packet_neighbors = WHEHeader.GetNeighbors();
  
  //Originまでのルーティングテーブルを取得
  RoutingTableEntry toOrigin;
  if (!m_routingTable.LookupRoute (rrepHeader.GetOrigin (), toOrigin) || toOrigin.GetFlag () == IN_SEARCH)
    {
      //printf("Impossible! drop.\n");
      return; // Impossible! drop.
    }

  uint16_t hop = toOrigin.GetHop();

  //RREPのセンダの隣接ノードリストと、パケット内の隣接ノードリストを比較
  int packet_size = packet_neighbors.size();
  int sender_size = sender_neighbors.size();

  int data_size = 6 + 4*packet_size;
  
  std::ofstream writing_file;
  std::string filename = "sample.txt";
  writing_file.open(filename, std::ios::app);
  // std::string writing_text = "";
  writing_file << data_size << std::endl;
  writing_file.close(); 

  for(int i= 0; i < sender_size; i++)
  {
    for(int j = 0; j < packet_size; j++)
    {
      if(sender_neighbors.at(i) == packet_neighbors.at(j) && !IsMyOwnAddress (sender_neighbors.at(i)))
      {
        //NS_LOG_UNCOND("一致したip addr: "<<sender_neighbors.at(i));

        if (m_WHEIdCache.IsDuplicate (rrepHeader.GetOrigin(), get_id))
        {
          NS_LOG_DEBUG ("Ignoring WHE due to duplicate");
          return;
        }
        printf("同一のノードを発見２, RREP送信  ID:%d\n", rrepHeader.Getid());

        //Send RREP
        Ptr<Packet> packet = Create<Packet> ();
        SocketIpTtlTag ttl;
        ttl.SetTtl (hop);
        packet->AddPacketTag (ttl);
        packet->AddHeader (rrepHeader);
        TypeHeader tHeader (AODVTYPE_RREP);
        packet->AddHeader (tHeader);
        Ptr<Socket> socket = FindSocketWithInterfaceAddress (toOrigin.GetInterface ());
        NS_ASSERT (socket);
        socket->SendTo (packet, 0, InetSocketAddress (toOrigin.GetNextHop (), AODV_PORT));
        
        return;
      }
    }
  }
    //int WH_List_size = WH_List.size();

    //1/2の確率で1と0のどちらかを出力します
    std::srand( time(NULL) );
    int rand = std::rand();

    int WH_at = rand  % 2;

    //WHノードの場合、rrepを偽造して送信
    //for(int k = 0; k < WH_List_size; k++)
    //{
    if(0){
      if(receiver == Ipv4Address("10.1.2.1") || receiver == Ipv4Address("10.0.0.2"))
      {

        if (m_WHEIdCache.IsDuplicate (rrepHeader.GetOrigin(), get_id))
          {
            NS_LOG_DEBUG ("Ignoring WHE due to duplicate");
            //printf("Ignoring WHE due to duplicate\n");
            return;
          }

        if(WH_at == 0)
        {
          WH2++;
          printf("検知に参加した回数：%d\n", WH2);
        }
        else
        {
          

          printf("------WHノードによりRREPを偽造------\n");

          WH1++;
          printf("偽造した回数:%d\n", WH1);
          //Send RREP
          Ptr<Packet> packet = Create<Packet> ();
          SocketIpTtlTag ttl;
          ttl.SetTtl (hop);
          packet->AddPacketTag (ttl);
          packet->AddHeader (rrepHeader);
          TypeHeader tHeader (AODVTYPE_RREP);
          packet->AddHeader (tHeader);
          Ptr<Socket> socket = FindSocketWithInterfaceAddress (toOrigin.GetInterface ());
          NS_ASSERT (socket);
          socket->SendTo (packet, 0, InetSocketAddress (toOrigin.GetNextHop (), AODV_PORT));
          return ;
        }
        return;
      }
    }
    //}
  

  //printf("何もせずに終了\n");

}

void
RoutingProtocol::RecvReplyAck (Ipv4Address neighbor) //RREP_ACKを受信します。
{
  NS_LOG_FUNCTION (this);

  RoutingTableEntry rt;
  if (m_routingTable.LookupRoute (neighbor, rt))
    {
      rt.m_ackTimer.Cancel ();
      rt.SetFlag (VALID);
      m_routingTable.Update (rt);
    }
}

void
RoutingProtocol::ProcessHello (RrepHeader const & rrepHeader, Ipv4Address receiver ) //hello メッセージを処理します。
{
  NS_LOG_FUNCTION (this << "from " << rrepHeader.GetDst ());
  /*
   *  ノードが近傍からHelloメッセージを受信するたびに、
      そのノードは近傍へのアクティブなルートがあることを確認し、
      必要であれば作成するべきである(SHOULD)。必要に応じて作成する。
   */
  RoutingTableEntry toNeighbor;
  if (!m_routingTable.LookupRoute (rrepHeader.GetDst (), toNeighbor))
    {
      Ptr<NetDevice> dev = m_ipv4->GetNetDevice (m_ipv4->GetInterfaceForAddress (receiver));
      RoutingTableEntry newEntry (/*device=*/ dev, /*dst=*/ rrepHeader.GetDst (), /*validSeqNo=*/ true, /*seqno=*/ rrepHeader.GetDstSeqno (),
                                              /*iface=*/ m_ipv4->GetAddress (m_ipv4->GetInterfaceForAddress (receiver), 0),
                                              /*hop=*/ 1, /*nextHop=*/ rrepHeader.GetDst (), /*lifeTime=*/ rrepHeader.GetLifeTime ());
      m_routingTable.AddRoute (newEntry);
    }
  else
    {
      toNeighbor.SetLifeTime (std::max (Time (m_allowedHelloLoss * m_helloInterval), toNeighbor.GetLifeTime ()));
      toNeighbor.SetSeqNo (rrepHeader.GetDstSeqno ());
      toNeighbor.SetValidSeqNo (true);
      toNeighbor.SetFlag (VALID);
      toNeighbor.SetOutputDevice (m_ipv4->GetNetDevice (m_ipv4->GetInterfaceForAddress (receiver)));
      toNeighbor.SetInterface (m_ipv4->GetAddress (m_ipv4->GetInterfaceForAddress (receiver), 0));
      toNeighbor.SetHop (1);
      toNeighbor.SetNextHop (rrepHeader.GetDst ());
      m_routingTable.Update (toNeighbor);
    }
  if (m_enableHello)
    {
      m_nb.Update (rrepHeader.GetDst (), Time (m_allowedHelloLoss * m_helloInterval));
    }
}

void
RoutingProtocol::RecvError (Ptr<Packet> p, Ipv4Address src ) //アドレス src のノードから RERR を受信します。
{
  NS_LOG_FUNCTION (this << " from " << src);
  RerrHeader rerrHeader;
  p->RemoveHeader (rerrHeader);
  std::map<Ipv4Address, uint32_t> dstWithNextHopSrc;
  std::map<Ipv4Address, uint32_t> unreachable;
  m_routingTable.GetListOfDestinationWithNextHop (src, dstWithNextHopSrc);
  std::pair<Ipv4Address, uint32_t> un;
  while (rerrHeader.RemoveUnDestination (un))
    {
      for (std::map<Ipv4Address, uint32_t>::const_iterator i =
             dstWithNextHopSrc.begin (); i != dstWithNextHopSrc.end (); ++i)
        {
          if (i->first == un.first)
            {
              unreachable.insert (un);
            }
        }
    }

  std::vector<Ipv4Address> precursors;
  for (std::map<Ipv4Address, uint32_t>::const_iterator i = unreachable.begin ();
       i != unreachable.end (); )
    {
      if (!rerrHeader.AddUnDestination (i->first, i->second))
        {
          TypeHeader typeHeader (AODVTYPE_RERR);
          Ptr<Packet> packet = Create<Packet> ();
          SocketIpTtlTag tag;
          tag.SetTtl (1);
          packet->AddPacketTag (tag);
          packet->AddHeader (rerrHeader);
          packet->AddHeader (typeHeader);
          SendRerrMessage (packet, precursors);
          rerrHeader.Clear ();
        }
      else
        {
          RoutingTableEntry toDst;
          m_routingTable.LookupRoute (i->first, toDst);
          toDst.GetPrecursors (precursors);
          ++i;
        }
    }
  if (rerrHeader.GetDestCount () != 0)
    {
      TypeHeader typeHeader (AODVTYPE_RERR);
      Ptr<Packet> packet = Create<Packet> ();
      SocketIpTtlTag tag;
      tag.SetTtl (1);
      packet->AddPacketTag (tag);
      packet->AddHeader (rerrHeader);
      packet->AddHeader (typeHeader);
      SendRerrMessage (packet, precursors);
    }
  m_routingTable.InvalidateRoutesWithDst (unreachable);
}

void
RoutingProtocol::RouteRequestTimerExpire (Ipv4Address dst) //ルート探索プロセスを処理します。
{
  NS_LOG_LOGIC (this);
  RoutingTableEntry toDst;
  if (m_routingTable.LookupValidRoute (dst, toDst))
    {
      //SendPacketFromQueue (dst, toDst.GetRoute ());
      NS_LOG_LOGIC ("route to " << dst << " found");
      // return;
    }
  /*
   * REPを受信することなく、最大TTLでRreqRetries回ルート探索を試行した場合、 
     対応するデスティネーション宛てのすべてのデータパケットはバッファから取り除かれるべきである[SHOULD]。
     バッファからドロップされるべきであり(SHOULD)、
     Destination Unreachable メッセージがアプリケーションに配送されるべきである(SHOULD)。
   */
  if (toDst.GetRreqCnt () == m_rreqRetries)
    {
      NS_LOG_LOGIC ("route discovery to " << dst << " has been attempted RreqRetries (" << m_rreqRetries << ") times with ttl " << m_netDiameter);
      m_addressReqTimer.erase (dst);
      m_routingTable.DeleteRoute (dst);
      NS_LOG_DEBUG ("Route not found. Drop all packets with dst " << dst);
      m_queue.DropPacketWithDst (dst);
      return;
    }

  if (toDst.GetFlag () == IN_SEARCH)
    {
      NS_LOG_LOGIC ("Resend RREQ to " << dst << " previous ttl " << toDst.GetHop ());
      SendRequest (dst);
    }
  else
    {
      NS_LOG_DEBUG ("Route down. Stop search. Drop packet with destination " << dst);
      m_addressReqTimer.erase (dst);
      m_routingTable.DeleteRoute (dst);
      m_queue.DropPacketWithDst (dst);
    }
}

void
RoutingProtocol::HelloTimerExpire () //次回の Hello メッセージの送信をスケジュールします。
{
  NS_LOG_FUNCTION (this);
  Time offset = Time (Seconds (0));
  if (m_lastBcastTime > Time (Seconds (0)))
    {
      offset = Simulator::Now () - m_lastBcastTime;
      NS_LOG_DEBUG ("Hello deferred due to last bcast at:" << m_lastBcastTime);
    }
  else
    {
      SendHello ();
    }
  m_htimer.Cancel ();
  Time diff = m_helloInterval - offset;
  m_htimer.Schedule (std::max (Time (Seconds (0)), diff));
  m_lastBcastTime = Time (Seconds (0));
}

void
RoutingProtocol::RreqRateLimitTimerExpire () //RREQ カウントをリセットし、RREQ レート制限タイマーを 1 秒の遅延でスケジュールします。
{
  NS_LOG_FUNCTION (this);
  m_rreqCount = 0;
  m_rreqRateLimitTimer.Schedule (Seconds (1));
}

void
RoutingProtocol::RerrRateLimitTimerExpire () //RERR カウントをリセットし、RERR レート制限タイマーを 1 秒の遅延でスケジュールします。
{
  NS_LOG_FUNCTION (this);
  m_rerrCount = 0;
  m_rerrRateLimitTimer.Schedule (Seconds (1));
}

void
RoutingProtocol::AckTimerExpire (Ipv4Address neighbor, Time blacklistTimeout) //blacklistTimeout に対して、隣接ノードへのリンクを単方向としてマークします。
{
  NS_LOG_FUNCTION (this);
  m_routingTable.MarkLinkAsUnidirectional (neighbor, blacklistTimeout);
}

void
RoutingProtocol::SendHello () //Helloメッセージを送信
{
  NS_LOG_FUNCTION (this);
  /* Broadcast a RREP with TTL = 1 with the RREP message fields set as follows:
   *   Destination IP Address         The node's IP address.
   *   Destination Sequence Number    The node's latest sequence number.
   *   Hop Count                      0
   *   Lifetime                       AllowedHelloLoss * HelloInterval
   */

  std::vector<Ipv4Address> List = {};
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j = m_socketAddresses.begin (); j != m_socketAddresses.end (); ++j)
    {
      Ptr<Socket> socket = j->first;
      Ipv4InterfaceAddress iface = j->second;

      RrepHeader helloHeader (/*prefix size=*/ 0, /*hops=*/ 0, /*dst=*/ iface.GetLocal (), /*dst seqno=*/ m_seqNo,
                                               /*origin=*/ iface.GetLocal (),/*lifetime=*/ Time (m_allowedHelloLoss * m_helloInterval), 
                                               /*隣接ノードリスト*/List, 0);
      Ptr<Packet> packet = Create<Packet> ();
      SocketIpTtlTag tag;
      tag.SetTtl (1);
      packet->AddPacketTag (tag);
      packet->AddHeader (helloHeader);
      TypeHeader tHeader (AODVTYPE_RREP);
      packet->AddHeader (tHeader);
      // 32アドレスの場合は全ホストにブロードキャスト送信、それ以外はサブネットに直接送信
      Ipv4Address destination;
      if (iface.GetMask () == Ipv4Mask::GetOnes ())
        {
          destination = Ipv4Address ("255.255.255.255");
        }
      else
        {
          destination = iface.GetBroadcast ();
        }
      Time jitter = Time (MilliSeconds (m_uniformRandomVariable->GetInteger (0, 10)));
      Simulator::Schedule (jitter, &RoutingProtocol::SendTo, this, socket, packet, destination);
    }
}

void
RoutingProtocol::SendPacketFromQueue (Ipv4Address dst, Ptr<Ipv4Route> route) //キューからのパケット送信
{
  NS_LOG_FUNCTION (this);
  QueueEntry queueEntry;
  while (m_queue.Dequeue (dst, queueEntry))
    {
      DeferredRouteOutputTag tag;
      Ptr<Packet> p = ConstCast<Packet> (queueEntry.GetPacket ());
      if (p->RemovePacketTag (tag)
          && tag.GetInterface () != -1
          && tag.GetInterface () != m_ipv4->GetInterfaceForDevice (route->GetOutputDevice ()))
        {
          NS_LOG_DEBUG ("Output device doesn't match. Dropped.");
          return;
        }
      UnicastForwardCallback ucb = queueEntry.GetUnicastForwardCallback ();//ユニキャストパケットを送信するためのコールバック
      Ipv4Header header = queueEntry.GetIpv4Header ();
      header.SetSource (route->GetSource ()); //ヘッダのソースノードを取得
      header.SetTtl (header.GetTtl () + 1); // 偽ループバック・ルーティングによる余分なTTLデクリメントを補う
     // ucb (route, p, header);
    }
}

void
RoutingProtocol::SendRerrWhenBreaksLinkToNextHop (Ipv4Address nextHop) //RERR を開始する
{
  NS_LOG_FUNCTION (this << nextHop);
  RerrHeader rerrHeader;
  std::vector<Ipv4Address> precursors;
  std::map<Ipv4Address, uint32_t> unreachable;

  RoutingTableEntry toNextHop;
  if (!m_routingTable.LookupRoute (nextHop, toNextHop))
    {
      return;
    }
  toNextHop.GetPrecursors (precursors);
  rerrHeader.AddUnDestination (nextHop, toNextHop.GetSeqNo ());
  m_routingTable.GetListOfDestinationWithNextHop (nextHop, unreachable);
  for (std::map<Ipv4Address, uint32_t>::const_iterator i = unreachable.begin (); i
       != unreachable.end (); )
    {
      if (!rerrHeader.AddUnDestination (i->first, i->second))
        {
          NS_LOG_LOGIC ("Send RERR message with maximum size.");
          TypeHeader typeHeader (AODVTYPE_RERR);
          Ptr<Packet> packet = Create<Packet> ();
          SocketIpTtlTag tag;
          tag.SetTtl (1);
          packet->AddPacketTag (tag);
          packet->AddHeader (rerrHeader);
          packet->AddHeader (typeHeader);
          SendRerrMessage (packet, precursors);
          rerrHeader.Clear ();
        }
      else
        {
          RoutingTableEntry toDst;
          m_routingTable.LookupRoute (i->first, toDst);
          toDst.GetPrecursors (precursors);
          ++i;
        }
    }
  if (rerrHeader.GetDestCount () != 0)
    {
      TypeHeader typeHeader (AODVTYPE_RERR);
      Ptr<Packet> packet = Create<Packet> ();
      SocketIpTtlTag tag;
      tag.SetTtl (1);
      packet->AddPacketTag (tag);
      packet->AddHeader (rerrHeader);
      packet->AddHeader (typeHeader);
      SendRerrMessage (packet, precursors);
    }
  unreachable.insert (std::make_pair (nextHop, toNextHop.GetSeqNo ()));
  m_routingTable.InvalidateRoutesWithDst (unreachable);
}

//入力パケットを転送するルートがない場合に RERR メッセージを送信します。
void
RoutingProtocol::SendRerrWhenNoRouteToForward (Ipv4Address dst,
                                               uint32_t dstSeqNo, Ipv4Address origin)
{
  NS_LOG_FUNCTION (this);
  // ノードは1秒間にRERR_RATELIMITを超えるRERRメッセージを発信すべきではない[SHOULD NOT]。
  if (m_rerrCount == m_rerrRateLimit)
    {
      // RerrRateLimitタイマーが実行中で、期限切れになることを確認してください。
      NS_ASSERT (m_rerrRateLimitTimer.IsRunning ());
      // パケットを破棄して返す
      NS_LOG_LOGIC ("RerrRateLimit reached at " << Simulator::Now ().GetSeconds () << " with timer delay left "
                                                << m_rerrRateLimitTimer.GetDelayLeft ().GetSeconds ()
                                                << "; suppressing RERR");
      return;
    }
  RerrHeader rerrHeader;
  rerrHeader.AddUnDestination (dst, dstSeqNo);
  RoutingTableEntry toOrigin;
  Ptr<Packet> packet = Create<Packet> ();
  SocketIpTtlTag tag;
  tag.SetTtl (1);
  packet->AddPacketTag (tag);
  packet->AddHeader (rerrHeader);
  packet->AddHeader (TypeHeader (AODVTYPE_RERR));
  if (m_routingTable.LookupValidRoute (origin, toOrigin))
    {
      Ptr<Socket> socket = FindSocketWithInterfaceAddress (
          toOrigin.GetInterface ());
      NS_ASSERT (socket);
      NS_LOG_LOGIC ("Unicast RERR to the source of the data transmission");
      socket->SendTo (packet, 0, InetSocketAddress (toOrigin.GetNextHop (), AODV_PORT));
    }
  else
    {
      for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator i =
             m_socketAddresses.begin (); i != m_socketAddresses.end (); ++i)
        {
          Ptr<Socket> socket = i->first;
          Ipv4InterfaceAddress iface = i->second;
          NS_ASSERT (socket);
          NS_LOG_LOGIC ("Broadcast RERR message from interface " << iface.GetLocal ());
          // 32アドレスの場合は全ホストにブロードキャスト送信、それ以外はサブネットに直接送信
          Ipv4Address destination;
          if (iface.GetMask () == Ipv4Mask::GetOnes ())
            {
              destination = Ipv4Address ("255.255.255.255");
            }
          else
            {
              destination = iface.GetBroadcast ();
            }
          socket->SendTo (packet->Copy (), 0, InetSocketAddress (destination, AODV_PORT));
        }
    }
}

void
RoutingProtocol::SendRerrMessage (Ptr<Packet> packet, std::vector<Ipv4Address> precursors)//RERRを転送。
{
  NS_LOG_FUNCTION (this);

  if (precursors.empty ())
    {
      NS_LOG_LOGIC ("No precursors");
      return;
    }
  // ノードは1秒間にRERR_RATELIMITを超えるRERRメッセージを発信すべきではない[SHOULD NOT]。
  if (m_rerrCount == m_rerrRateLimit)
    {
      // RerrRateLimitタイマーが実行中で、期限切れになることを確認してください。
      NS_ASSERT (m_rerrRateLimitTimer.IsRunning ());
      // パケットを破棄して返す
      NS_LOG_LOGIC ("RerrRateLimit reached at " << Simulator::Now ().GetSeconds () << " with timer delay left "
                                                << m_rerrRateLimitTimer.GetDelayLeft ().GetSeconds ()
                                                << "; suppressing RERR");
      return;
    }
  //プリカーサ(precursor)が1つしかない場合、RERRはそのプリカーサに向けてユニキャストされるべきである(SHOULD)
  if (precursors.size () == 1)
    {
      RoutingTableEntry toPrecursor;
      if (m_routingTable.LookupValidRoute (precursors.front (), toPrecursor))
        {
          Ptr<Socket> socket = FindSocketWithInterfaceAddress (toPrecursor.GetInterface ());
          NS_ASSERT (socket);
          NS_LOG_LOGIC ("one precursor => unicast RERR to " << toPrecursor.GetDestination () << " from " << toPrecursor.GetInterface ().GetLocal ());
          Simulator::Schedule (Time (MilliSeconds (m_uniformRandomVariable->GetInteger (0, 10))), &RoutingProtocol::SendTo, this, socket, packet, precursors.front ());
          m_rerrCount++;
        }
      return;
    }

  //  破断したルートのプリカーサノードがあるインターフェイスでのみRERRを送信すること。
  std::vector<Ipv4InterfaceAddress> ifaces;
  RoutingTableEntry toPrecursor;
  for (std::vector<Ipv4Address>::const_iterator i = precursors.begin (); i != precursors.end (); ++i)
    {
      if (m_routingTable.LookupValidRoute (*i, toPrecursor)
          && std::find (ifaces.begin (), ifaces.end (), toPrecursor.GetInterface ()) == ifaces.end ())
        {
          ifaces.push_back (toPrecursor.GetInterface ());
        }
    }

  for (std::vector<Ipv4InterfaceAddress>::const_iterator i = ifaces.begin (); i != ifaces.end (); ++i)
    {
      Ptr<Socket> socket = FindSocketWithInterfaceAddress (*i);
      NS_ASSERT (socket);
      NS_LOG_LOGIC ("Broadcast RERR message from interface " << i->GetLocal ());
      // std::cout << "Broadcast RERR message from interface " << i->GetLocal () << std::endl;
      // 32アドレスの場合は全ホストにブロードキャスト送信、それ以外はサブネットに直接送信
      Ptr<Packet> p = packet->Copy ();
      Ipv4Address destination;
      if (i->GetMask () == Ipv4Mask::GetOnes ())
        {
          destination = Ipv4Address ("255.255.255.255");
        }
      else
        {
          destination = i->GetBroadcast ();
        }
      Simulator::Schedule (Time (MilliSeconds (m_uniformRandomVariable->GetInteger (0, 10))), &RoutingProtocol::SendTo, this, socket, p, destination);
    }
}

Ptr<Socket>
RoutingProtocol::FindSocketWithInterfaceAddress (Ipv4InterfaceAddress addr ) const
{
  NS_LOG_FUNCTION (this << addr);
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j =
         m_socketAddresses.begin (); j != m_socketAddresses.end (); ++j)
    {
      Ptr<Socket> socket = j->first;
      Ipv4InterfaceAddress iface = j->second;
      if (iface == addr)
        {
          return socket;
        }
    }
  Ptr<Socket> socket;
  return socket;
}

Ptr<Socket>
RoutingProtocol::FindSubnetBroadcastSocketWithInterfaceAddress (Ipv4InterfaceAddress addr ) const
{
  NS_LOG_FUNCTION (this << addr);
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j =
         m_socketSubnetBroadcastAddresses.begin (); j != m_socketSubnetBroadcastAddresses.end (); ++j)
    {
      Ptr<Socket> socket = j->first;
      Ipv4InterfaceAddress iface = j->second;
      if (iface == addr)
        {
          return socket;
        }
    }
  Ptr<Socket> socket;
  return socket;
}

void
RoutingProtocol::DoInitialize (void)
{
  NS_LOG_FUNCTION (this);
  uint32_t startTime;
  if (m_enableHello)
    {
      m_htimer.SetFunction (&RoutingProtocol::HelloTimerExpire, this);
      startTime = m_uniformRandomVariable->GetInteger (0, 100);
      NS_LOG_DEBUG ("Starting at time " << startTime << "ms");
      m_htimer.Schedule (MilliSeconds (startTime));
    }
  Ipv4RoutingProtocol::DoInitialize ();
}

} //namespace aodv
} //namespace ns3
