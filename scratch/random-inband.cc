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
 * This is an example script for AODV manet routing protocol. 
 *
 * Authors: Pavel Boyko <boyko@iitp.ru>
 */

#include <iostream>
#include <cmath>
#include "ns3/aodv-module.h"
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/v4ping-helper.h"
#include "ns3/yans-wifi-helper.h"
#include "ns3/flow-monitor-module.h"
//追加部分
#include "ns3/applications-module.h"
#include "ns3/wifi-module.h"
#include "ns3/netanim-module.h"
#include "myapp.h"
#include "ns3/out-band-wh-module.h"
// #include <filesystem>

#include <sys/stat.h>
#include <cstdio>      // ★remove() を使うなら入れておくと確実

using namespace ns3;


std::ofstream ofs;

//ファイルを更新または作成
// ===== filesystem を使わない mkdir -p 相当 =====
static std::string
GetParentDir(const std::string& filepath)
{
    const std::string::size_type pos = filepath.find_last_of('/');
    if (pos == std::string::npos)
    {
        return ""; // 親ディレクトリなし
    }
    if (pos == 0)
    {
        return "/"; // ルート直下
    }
    return filepath.substr(0, pos);
}

static void
CreateDirectoriesRecursive(const std::string& dir)
{
    if (dir.empty() || dir == "/")
    {
        return;
    }

    std::string cur;
    cur.reserve(dir.size());

    // 先頭が '/' の場合は絶対パスとして開始
    if (!dir.empty() && dir[0] == '/')
    {
        cur = "/";
    }

    // "a/b/c" を a -> a/b -> a/b/c の順に mkdir する
    for (size_t i = (cur == "/" ? 1 : 0); i < dir.size(); ++i)
    {
        const char c = dir[i];
        cur.push_back(c);

        if (c == '/' || i + 1 == dir.size())
        {
            // 末尾の '/' は mkdir 前に除去（ただし "/" は除外）
            while (cur.size() > 1 && cur.back() == '/')
            {
                cur.pop_back();
            }

            if (!cur.empty() && cur != "/")
            {
                if (::mkdir(cur.c_str(), 0755) != 0)
                {
                    if (errno != EEXIST)
                    {
                        NS_FATAL_ERROR("Cannot create directory: " << cur
                                      << " errno=" << errno << " (" << std::strerror(errno) << ")");
                    }
                }
            }

            // 次の階層用に "/" を戻す（末尾が '/' でなければ）
            if (i + 1 < dir.size() && dir[i] != '/')
            {
                cur.push_back('/');
            }
        }
    }
}

// ファイルを追記で開く（なければ作成）＋ 親ディレクトリを作成
void
OpenLogFileOverwrite(std::ofstream& ofs, const std::string& filepath)
{
    const std::string parent = GetParentDir(filepath);

    // 親ディレクトリがあれば作成（mkdir -p 相当）
    if (!parent.empty() && parent != "/")
    {
        CreateDirectoriesRecursive(parent);
    }

    // 追記モードで open（存在すれば末尾に追記）
    ofs.open(filepath.c_str(), std::ios::out | std::ios::app);

    if (!ofs.is_open())
    {
        NS_FATAL_ERROR("Cannot open result file: " << filepath);
    }
}

/**
 * \ingroup aodv-examples
 * \ingroup examples
 * \brief Test script.
 * 
 * This script creates 1-dimensional grid topology and then ping last node from the first one:
 * 
 * [10.0.0.1] <-- step --> [10.0.0.2] <-- step --> [10.0.0.3] <-- step --> [10.0.0.4]
 * 
 * ping 10.0.0.4
 *
 * When 1/3 of simulation time has elapsed, one of the nodes is moved out of
 * range, thereby breaking the topology.  By default, this will result in
 * only 34 of 100 pings being received.  If the step size is reduced
 * to cover the gap, then all pings can be received.
 */
class AodvExample 
{
public:
  AodvExample ();
  /**
   * \brief Configure script parameters
   * \param argc is the command line argument count
   * \param argv is the command line arguments
   * \return true on successful configuration
  */
  bool Configure (int argc, char **argv);
  /// Run simulation
  void Run ();
  /**
   * Report results
   * \param os the output stream
   */
  void Report (std::ostream & os);

private:

  // parameters
  /// Number of nodes
  uint32_t size;
  // parameters
  /// Number of around nodes
  uint32_t size_a;
  /// Distance between nodes, meters
  double step;
  /// Simulation time, seconds
  double totalTime;
  /// Write per-device PCAP traces if true
  bool pcap;
  /// Print routes if true
  bool printRoutes;

  //結果を保存するファイル
  std::string result_file;

  //結果を保存するモード
  int result_mode;

  //WHリンクの長さ
  int WH_size;

  //検知待機時間
  double wait_time;

  //エンド間の距離
  int end_distance;

  //シード値を決定するためのイテレーション
  int iteration;

  //WH攻撃のモード 0 =  攻撃なし、1 = 内部WH攻撃、2 = 外部WH攻撃
  uint8_t whmode;

  int forwardmode;  //0 = 全パケット転送  1 = RREQとRREPのみ転送

  // network
  /// nodes used in the example
  NodeContainer nodes;
 
  //追加部分
  NodeContainer not_malicious;
  NodeContainer malicious;
  //ここまで

  /// devices used in the example
  NetDeviceContainer devices, mal_devices;
  /// interfaces used in the example
  Ipv4InterfaceContainer interfaces;

  Ipv4InterfaceContainer mal_ifcont;

private:
  /// Create the nodes
  void CreateNodes ();
  /// Create the devices
  void CreateDevices ();
  /// Create the network
  void InstallInternetStack ();
  /// Create the simulation applications
  void InstallApplications ();
};

void
ReceivePacket(Ptr<const Packet> p, const Address & addr)
{
	std::cout << Simulator::Now ().GetSeconds () << "\t" << p->GetSize() <<"\n";
}

int main (int argc, char **argv)
{
  AodvExample test;
  if (!test.Configure (argc, argv))
    NS_FATAL_ERROR ("Configuration failed. Aborted.");

  test.Run ();
  // test.Report (std::cout);
  return 0;
}

//-----------------------------------------------------------------------------
AodvExample::AodvExample () :
  size (400),
  size_a (5),
  step (50),
  totalTime (30),
  pcap (false),
  printRoutes (false),
  result_file("deff/p-log.csv"), //結果を保存するファイル
  result_mode(2),
  WH_size(350),
  end_distance(800), //エンド間の距離
  iteration(1), //イテレーション
  whmode(1),
  forwardmode(0)
{
}

bool
AodvExample::Configure (int argc, char **argv)
{
  // Enable AODV logs by default. Comment this if too noisy
  //LogComponentEnable("AodvRoutingProtocol", LOG_LEVEL_ALL);
  //LogComponentEnable ("UdpEchoClientApplication", LOG_LEVEL_ALL);
  //LogComponentEnable ("UdpEchoServerApplication", LOG_LEVEL_ALL);

  CommandLine cmd;

  cmd.AddValue ("pcap", "Write PCAP traces.", pcap);
  cmd.AddValue ("printRoutes", "Print routing table dumps.", printRoutes);
  cmd.AddValue ("size", "Number of nodes.", size);
  cmd.AddValue ("time", "Simulation time, s.", totalTime);
  cmd.AddValue ("step", "Grid step, m", step);

  cmd.AddValue("result_file", "result file", result_file);
  cmd.AddValue("result_mode", "result mode", result_mode); //1=ご検知率と検知コスト　2=検知率　3=経路作成時間
  cmd.AddValue("WH_size", "WH size", WH_size); //WHの長さ
  cmd.AddValue("end_distance", "end distance", end_distance); //エンド間の距離
  cmd.AddValue("iteration", "iteration", iteration); //イテレーション
  cmd.AddValue("forwardmode", "forwardmode", forwardmode); //イテレーション

  cmd.Parse (argc, argv);

  SeedManager::SetSeed (iteration);

  if(end_distance -WH_size - 110 < 30)
  {
      std::cerr << "エンド間の距離がWHリンクの長さよりも短いです。" << std::endl;
      return false;
  }

  return true;
}

void
AodvExample::Run ()
{
//  Config::SetDefault ("ns3::WifiRemoteStationManager::RtsCtsThreshold", UintegerValue (1)); // enable rts cts all the time.
  CreateNodes ();
  CreateDevices ();
  InstallInternetStack ();
  InstallApplications ();

  std::cout << "Starting simulation for " << totalTime << " s ...\n";

  Simulator::Stop (Seconds (totalTime));

  //追加部分
  FlowMonitorHelper flowMonitor;
  auto monitor = flowMonitor.InstallAll();

  Simulator::Run ();
  Report(std::cout);
  Simulator::Destroy ();
}

static bool NeedHeaderByIostream(const std::string& path)
{
    std::ifstream ifs(path, std::ios::in);
    if (!ifs.good())
    {
        return true; // 開けない=存在しない扱い → ヘッダー必要
    }
    ifs.seekg(0, std::ios::end);
    return (ifs.tellg() == 0);
}

void
AodvExample::Report (std::ostream &)
{ 
    bool needHeader = NeedHeaderByIostream(result_file);
    
  // ★ 出力ファイルを開く（追記 or 上書き）
    OpenLogFileOverwrite(ofs,result_file);

    uint32_t totalTP = 0, totalFN = 0, totalFP = 0, totalTN = 0, totalNA = 0;
    uint64_t totalBytes = 0;
    uint32_t totalforwardedHello = 0;
    std::vector<double> latencies;
    uint32_t latencyCount = 0;
    Time totalRouteTime = Seconds(0);

    if (needHeader)
    {
        ofs << "seed,nodes,wh_mode,forwardmode,end_distance,"
            << "tp,fn,fp,tn,"
            << "wh_detection_rate,false_positive_rate,"
            << "total_ctrl_bytes,avg_route_latency\n";
    }

    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        Ptr<Ipv4> ipv4 = nodes.Get(i)->GetObject<Ipv4>();
        Ptr<Ipv4RoutingProtocol> rp = ipv4->GetRoutingProtocol();
        Ptr<aodv::RoutingProtocol> aodv = DynamicCast<aodv::RoutingProtocol>(rp);
        if (!aodv) continue;

        auto stats = aodv->Getevaluation();

        totalTP += stats.detectedWh;
        totalFN += stats.undetectedWh;
        totalFP += stats.falsePositive;
        totalTN += stats.truenegative;
        totalNA += stats.notApplicable;
        totalBytes += stats.totalAodvCtrlBytes;
        totalforwardedHello += stats.helloForwardedCount;

        if(stats.Getroute)
        {
          latencyCount++;
          totalRouteTime += stats.m_routetime;
        }


        // for (const auto &kv : stats.m_latencyTable)
        // {
        //     const auto &entry = kv.second;
        //     if (entry.latency.GetSeconds() > 0)
        //         latencies.push_back(entry.latency.GetSeconds());
        // }
    }

    double detectionRate = (totalTP + totalFN > 0)
                           ? (double)totalTP / (totalTP + totalFN)
                           : 0.0;

    double falsePositiveRate = (totalFP + totalTN > 0)
                               ? (double)totalFP / (totalFP + totalTN)
                               : 0.0;

    double avgLatencySec = 0.0;
    if (latencyCount > 0)
    {
        // Time は「秒」にしてから double 平均が安全
        avgLatencySec = totalRouteTime.GetSeconds() / static_cast<double>(latencyCount);
    }

    // if (!latencies.empty()) {
    //     double sum = 0;
    //     for (double v : latencies) sum += v;
    //     avgLatency = sum / latencies.size();
    // }

     ofs << iteration << ","
        << size << ","
        << whmode << ","               // WhMode
        << forwardmode << ","
        << end_distance << ","
        << totalTP << ","
        << totalFN << ","
        << totalFP << ","
        << totalTN << ","
        << detectionRate << ","
        << falsePositiveRate << ","
        << totalBytes << ","
        << avgLatencySec << "\n";

    ofs.close();
}

void
AodvExample::CreateNodes ()
{

  //ルートノードの作製
  std::cout << "Creating " << (unsigned)size << " nodes " << step << " m apart.\n";
  nodes.Create (size);
  // Name nodes
  for (uint32_t i = 0; i < size; ++i)
  {
    std::ostringstream os;
    os << "node-" << i;
    Names::Add (os.str (), nodes.Get (i));
  }
  //固定ノード
  NodeContainer fixedNodes;
  //移動ノード
  NodeContainer mobileNodes;

  for (uint32_t i = 0; i < size; ++i) {
      if(i == 0 || i == size - 1 
         || i == 1 || i == 2 //WHノード
         || i == 3 || i == 4 //送受信ノード
         || i == 5 || i == 6 //送受信ノード
        ) {
          // 固定ノードとして追加
          fixedNodes.Add(nodes.Get(i));
      }
      else
      {
          // 移動ノードとして追加
          mobileNodes.Add(nodes.Get(i));
      }
  }

  uint32_t total = mobileNodes.GetN();
  uint32_t half  = total / 2;

  NodeContainer carNodes;
  NodeContainer pedestrianNodes;

  for (uint32_t i = 0; i < total; ++i)
  {
      if (i < half)
      {
          carNodes.Add(mobileNodes.Get(i));
      }
      else
      {
          pedestrianNodes.Add(mobileNodes.Get(i));
      }
  }

  // //ノードをランダムに配置
  // MobilityHelper mobility;
  // mobility.SetPositionAllocator ("ns3::RandomRectanglePositionAllocator",
  //                               "X", StringValue("ns3::UniformRandomVariable[Min=0|Max=300]"),
  //                               "Y", StringValue("ns3::UniformRandomVariable[Min=-100|Max=100]")
  //                               );
  
  // mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");

  // mobility.Install(nodes);

  // ===============================
  // 共通 PositionAllocator ノードをランダムに配置
  // ===============================
  Ptr<PositionAllocator> positionAlloc =
      CreateObject<RandomRectanglePositionAllocator>();
  positionAlloc->SetAttribute("X",
      StringValue("ns3::UniformRandomVariable[Min=0|Max=800]"));
  positionAlloc->SetAttribute("Y",
      StringValue("ns3::UniformRandomVariable[Min=0|Max=800]"));

  // ===============================
  // 自動車ノード（11–16 m/s）
  // ===============================
  MobilityHelper carMobility;
  carMobility.SetPositionAllocator(positionAlloc);
  carMobility.SetMobilityModel(
        "ns3::RandomWaypointMobilityModel",
        "Speed", StringValue("ns3::UniformRandomVariable[Min=6|Max=13.888889]"),
        "Pause", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=5.0]"),
        "PositionAllocator", PointerValue(positionAlloc)
    );
  carMobility.Install(carNodes);

  // ===============================
  // 歩行者ノード（1–5 m/s）
  // ===============================
  MobilityHelper pedestrianMobility;
  pedestrianMobility.SetPositionAllocator(positionAlloc);
  pedestrianMobility.SetMobilityModel(
      "ns3::RandomWaypointMobilityModel",
      "Speed", StringValue("ns3::UniformRandomVariable[Min=1.0|Max=5.0]"),
      "Pause", StringValue("ns3::ConstantRandomVariable[Constant=0.0]"),
      "PositionAllocator", PointerValue(positionAlloc)
  );
  pedestrianMobility.Install(pedestrianNodes);

  MobilityHelper fixedMobility;

  // 固定ノードの位置を設定
  Ptr<ListPositionAllocator> fixedpositionAlloc = CreateObject<ListPositionAllocator>();
  fixedpositionAlloc->Add(Vector(0, 400, 0));  //送信者の位置情報　ID=0

  fixedpositionAlloc->Add(Vector(end_distance - WH_size - 110, 400, 0));  //WH1の位置情報　ID:1
  fixedpositionAlloc->Add(Vector(end_distance - 110, 400, 0));  //WH2の位置情報            ID:2

  fixedpositionAlloc->Add(Vector(0, 500, 0));  //送信ノード２            ID:3
  fixedpositionAlloc->Add(Vector(end_distance, 300, 0));  //受信ノード2         ID:4

  fixedpositionAlloc->Add(Vector(0, 300, 0));  //送信ノード３           ID:5
  fixedpositionAlloc->Add(Vector(end_distance, 500, 0));  //受信者ノード3  ID:6
  
  fixedpositionAlloc->Add(Vector(end_distance, 400, 0));  //受信者の位置情報  ID=size-1

  fixedMobility.SetPositionAllocator(fixedpositionAlloc);
  
  fixedMobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");

  fixedMobility.Install (fixedNodes);

  for (uint32_t i = 0; i < nodes.GetN(); i++)
  {
      //s正常ノードのノードコンテナ
      if (i != 1 && i != 2)
      {
          not_malicious.Add(nodes.Get(i));
      }
  }
  
  malicious.Add(nodes.Get(1));
  malicious.Add(nodes.Get(2));


  // MobilityHelper mobility;
  // Ptr<ListPositionAllocator> positionAlloc = CreateObject <ListPositionAllocator>();
  // positionAlloc ->Add(Vector(0, 0, 0)); // node0
  // positionAlloc ->Add(Vector(40, -10, 0)); // node1
  // positionAlloc ->Add(Vector(80, -10, 0)); // node2
  // positionAlloc ->Add(Vector(40, -10, 0)); // node3
  // positionAlloc ->Add(Vector(80, -10, 0)); // node4
  // positionAlloc ->Add(Vector(120, 0, 0)); // node5
  // // positionAlloc ->Add(Vector(20, -10, 0)); // node6
  // // positionAlloc ->Add(Vector(60, -10, 0)); // node7
  // // positionAlloc ->Add(Vector(100, -10, 0)); // node8
  // // positionAlloc ->Add(Vector(120, 0, 0)); //dst 9
  // // positionAlloc ->Add(Vector(200, 0, 0)); // node2
  // // positionAlloc ->Add(Vector(25, 25, 0)); // node2
  // // positionAlloc ->Add(Vector(75, 25, 0)); // node2
  // mobility.SetPositionAllocator(positionAlloc);
  // mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
  // mobility.Install(nodes);


  //    AnimationInterface anim ("wormhole.xml"); // Mandatory
  // AnimationInterface::SetConstantPosition (nodes.Get (0), 0, 0);
  // AnimationInterface::SetConstantPosition (nodes.Get (1), 100, 0);//WH1
  // AnimationInterface::SetConstantPosition (nodes.Get (2), 200, 0);//WH2
  // AnimationInterface::SetConstantPosition (nodes.Get (3), 250, 0);
  // AnimationInterface::SetConstantPosition (nodes.Get (4), 50, 0);
  // AnimationInterface::SetConstantPosition (nodes.Get (5), 275, 20);
  // AnimationInterface::SetConstantPosition (nodes.Get (size - 1), 300, 0);
  
  // anim.EnablePacketMetadata(true);

}

void
AodvExample::CreateDevices ()
{
  WifiHelper wifi;

  // ★2.4GHz帯(802.11g)に寄せる：5GHz(802.11a)より到達距離が出やすい
  wifi.SetStandard (WIFI_PHY_STANDARD_80211g);

  // ★802.11g の OFDM 6Mbps は "ErpOfdmRate6Mbps"
  wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
                                "DataMode", StringValue ("ErpOfdmRate6Mbps"),
                                "ControlMode", StringValue ("ErpOfdmRate6Mbps"),
                                // ★隠れ端末が多い(多ノード)なら RTS/CTS を強制（PDRが上がりやすい）
                                // 0=常にRTS/CTS, 2347=無効
                                "RtsCtsThreshold", UintegerValue (0));

  WifiMacHelper mac;
  mac.SetType ("ns3::AdhocWifiMac");

  YansWifiPhyHelper phy = YansWifiPhyHelper::Default ();

  // ★送信電力を少し上げる（80mでの受信電力に余裕を作る）
  phy.Set ("TxPowerStart", DoubleValue (20.0));
  phy.Set ("TxPowerEnd",   DoubleValue (20.0));

  // ★受信機の雑音指数（現実寄り）
  phy.Set ("RxNoiseFigure", DoubleValue (7.0));

  // ★感度寄りに（拾いにくいならさらに下げる：-92〜-96あたり）set
  phy.Set ("EnergyDetectionThreshold", DoubleValue (-94.0));
  phy.Set ("CcaEdThreshold",           DoubleValue (-97.0));

  // ---- Channel / Propagation ----
  YansWifiChannelHelper channel;
  channel.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");

  // ★ログ距離：Exponent を少し緩め（見通し屋外〜やや遮蔽くらいのイメージ）
  // ReferenceLoss は 2.4GHzで 1mの自由空間損失に近い値（目安 40dB前後）
  channel.AddPropagationLoss ("ns3::LogDistancePropagationLossModel",
                              "Exponent",          DoubleValue (2.7),
                              "ReferenceDistance", DoubleValue (1.0),
                              "ReferenceLoss",     DoubleValue (40.0));

  // ★まずは Nakagami を外して “平均挙動を安定化” させる（PDR改善確認が先）
  // もし「揺らぎも入れたい」なら後で追加（下に追記）

  // ★上限クリップ（80m間隔なら 120m くらいにして余裕を見るのが無難）
  channel.AddPropagationLoss ("ns3::RangePropagationLossModel",
                              "MaxRange", DoubleValue (100.0));

  phy.SetChannel (channel.Create ());

  devices = wifi.Install (phy, mac, nodes);


  PointToPointHelper pointToPoint;
  pointToPoint.SetDeviceAttribute ("DataRate", StringValue ("5Mbps"));

  // ptop遅延 = 40ms * m_whsize/100
  Time ptopDelay = MilliSeconds (40.0 * static_cast<double>(WH_size) / 100.0);
  pointToPoint.SetChannelAttribute ("Delay", TimeValue (ptopDelay));

  // NetDeviceContainer devices;
  mal_devices = pointToPoint.Install (malicious);

  if (pcap)
  {
    phy.EnablePcapAll ("aodv");
  }
}

void
AodvExample::InstallInternetStack ()
{
  AodvHelper aodv;
  PointToPointHelper point;

  aodv.Set("DestinationOnly", BooleanValue(false));
  aodv.Set("WhMode", UintegerValue(whmode));  // 0 = 通常ノードのみ、1 = 内部WH攻撃、2 = 外部WH攻撃

  // you can configure AODV attributes here using aodv.Set(name, value)
  InternetStackHelper stack;
  stack.SetRoutingHelper (aodv); // has effect on the next Install ()
  stack.Install (nodes);

  Ipv4AddressHelper address;
  address.SetBase ("10.0.0.0", "255.0.0.0","0.0.0.1");
  interfaces = address.Assign (devices);

  address.SetBase ("10.1.2.0", "255.255.255.0", "0.0.0.1");
  mal_ifcont = address.Assign (mal_devices);

  if (printRoutes)
    {
      Ptr<OutputStreamWrapper> routingStream = Create<OutputStreamWrapper> ("aodv.routes", std::ios::out);
      aodv.PrintRoutingTableAllAt (Seconds (8), routingStream);
    }
}

void
AodvExample::InstallApplications ()
{
  // ================================
  // 1つ目の送信ノード（ID = 0 → 受信者 ID = size - 1）
  // ================================
  Ipv4Address dst1 = interfaces.GetAddress(size - 1); // 受信者
  V4PingHelper ping1(dst1);
  ping1.SetAttribute ("Verbose", BooleanValue (true));
  ApplicationContainer app1 = ping1.Install(nodes.Get(0));  // 送信者
  app1.Start(Seconds(0));
  app1.Stop(Seconds(totalTime) - Seconds(0.001));


  // ================================
  // 2つ目の送信ノード（ID = 3 → 受信者 ID = 4）
  // ================================
  Ipv4Address dst2 = interfaces.GetAddress(4);
  V4PingHelper ping2(dst2);
  ping2.SetAttribute ("Verbose", BooleanValue (true));
  ApplicationContainer app2 = ping2.Install(nodes.Get(3));  // 送信者
  app2.Start(Seconds(0));
  app2.Stop(Seconds(totalTime) - Seconds(0.001));


  // ================================
  // 3つ目の送信ノード（ID = 5 → 受信者 ID = 6）
  // ================================
  Ipv4Address dst3 = interfaces.GetAddress(6);
  V4PingHelper ping3(dst3);
  ping3.SetAttribute ("Verbose", BooleanValue (true));
  ApplicationContainer app3 = ping3.Install(nodes.Get(5));  // 送信者
  app3.Start(Seconds(0));
  app3.Stop(Seconds(totalTime) - Seconds(0.001));

  // ---- 外部 WH アプリケーションの設定 ----
  // node1: ENTRY 側（wifi をスニファして、node2 の p2p IP にトンネル送信）
  {
      Ptr<WormholeApp> whEntry = CreateObject<WormholeApp>();

      //0 = 全パケット転送   1 = RREQとRREPのみ転送
      whEntry->SetAttribute ("ForwardMode", UintegerValue (forwardmode));

      whEntry->Setup(
          devices.Get(1),                 // node1 の wifi デバイス
          mal_ifcont.GetAddress(1),      // 相方 (node2) の p2p IP
          50000                               // UDP ポート
      );
      nodes.Get(1)->AddApplication(whEntry);
      whEntry->SetStartTime(Seconds(0.0));
      whEntry->SetStopTime(Seconds(totalTime));
  }

  // node2: EXIT 側（wifi をスニファしつつ、p2p からのトンネルを受けて wifi に再注入）
  {
      Ptr<WormholeApp> whExit = CreateObject<WormholeApp>();

      //0 = 全パケット転送   1 = RREQとRREPのみ転送
      whExit->SetAttribute ("ForwardMode", UintegerValue (forwardmode));

      whExit->Setup(
          devices.Get(2),                 // node2 の wifi デバイス
          mal_ifcont.GetAddress(0),      // 相方 (node1) の p2p IP
          50000
      );
      nodes.Get(2)->AddApplication(whExit);
      whExit->SetStartTime(Seconds(0.0));
      whExit->SetStopTime(Seconds(totalTime));
  }
}

