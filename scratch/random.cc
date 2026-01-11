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
  totalTime (50),
  pcap (true),
  printRoutes (true)
{
}

bool
AodvExample::Configure (int argc, char **argv)
{
  // Enable AODV logs by default. Comment this if too noisy
  //LogComponentEnable("AodvRoutingProtocol", LOG_LEVEL_ALL);
  //LogComponentEnable ("UdpEchoClientApplication", LOG_LEVEL_ALL);
  //LogComponentEnable ("UdpEchoServerApplication", LOG_LEVEL_ALL);



  SeedManager::SetSeed (12345);
  CommandLine cmd;

  cmd.AddValue ("pcap", "Write PCAP traces.", pcap);
  cmd.AddValue ("printRoutes", "Print routing table dumps.", printRoutes);
  cmd.AddValue ("size", "Number of nodes.", size);
  cmd.AddValue ("time", "Simulation time, s.", totalTime);
  cmd.AddValue ("step", "Grid step, m", step);

  cmd.Parse (argc, argv);
  return true;
}

void
AodvExample::Run ()
{
//  Config::SetDefault ("ns3::WifiRemoteStationManager::RtsCtsThreshold", UintegerValue (1)); // enable rts cts all the time.
  std::cout << "[DBG] CreateNodes\n";
  CreateNodes ();
  std::cout << "[DBG] CreateDevices\n";
  CreateDevices ();
  std::cout << "[DBG] InstallInternetStack\n";
  InstallInternetStack ();
  std::cout << "[DBG] InstallApplications\n";
  InstallApplications ();
  std::cout << "[DBG] Starting simulation...\n";

  std::cout << "Starting simulation for " << totalTime << " s ...\n";

  Simulator::Stop (Seconds (totalTime));

  //追加部分
  FlowMonitorHelper flowMonitor;
  auto monitor = flowMonitor.InstallAll();

  Simulator::Run ();
  Report(std::cout);
  Simulator::Destroy ();
}

void
AodvExample::Report (std::ostream &)
{ 
  // ★ 出力ファイルを開く（追記 or 上書き）
    OpenLogFileOverwrite(ofs,"deff/p-log-test2.csv");

    uint32_t totalTP = 0, totalFN = 0, totalFP = 0, totalTN = 0, totalNA = 0;
    uint64_t totalBytes = 0;
    uint32_t totalforwardedHello = 0;
    std::vector<double> latencies;
    uint32_t latencyCount = 0;
    Time totalRouteTime = Seconds(0);

    // ===== ヘッダはファイルが空のときだけ =====
    static bool headerWritten = false;
    if (!headerWritten)
    {
        ofs << "seed,nodes,wh_mode,end_distance,"
            << "tp,fn,fp,tn,"
            << "wh_detection_rate,false_positive_rate,"
            << "total_ctrl_bytes,avg_route_latency,totalforwardedHello\n";
        headerWritten = true;
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

     ofs << 1 << ","
        << size << ","
        << 2 << ","               // WhMode
        << 200 << ","
        << totalTP << ","
        << totalFN << ","
        << totalFP << ","
        << totalTN << ","
        << detectionRate << ","
        << falsePositiveRate << ","
        << totalBytes << ","
        << avgLatencySec << ","
        << totalforwardedHello << "\n";

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
  // Create static grid
  // MobilityHelper mobility;
  // mobility.SetPositionAllocator ("ns3::GridPositionAllocator",
  //                                "MinX", DoubleValue (0.0),
  //                                "MinY", DoubleValue (0.0),
  //                                "DeltaX", DoubleValue (step),
  //                                "DeltaY", DoubleValue (10000),
  //                                "GridWidth", UintegerValue (size),
  //                                "LayoutType", StringValue ("RowFirst"));
  // mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  // mobility.Install (nodes);

  //ノードをランダムに配置
  MobilityHelper mobility;
  mobility.SetPositionAllocator ("ns3::RandomRectanglePositionAllocator",
                                "X", StringValue("ns3::UniformRandomVariable[Min=0|Max=800]"),
                                "Y", StringValue("ns3::UniformRandomVariable[Min=-100|Max=800]")
                                );
  
  mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");

  mobility.Install(nodes);

//   for (uint32_t i = 0; i < nodes.GetN(); i++)
//     {
//         //攻撃者ノード以外にAODVをインストール
//         if (i != 1 && i != 2)
//         {
//             not_malicious.Add(nodes.Get(i));
//         }
//     }
  
//   malicious.Add(nodes.Get(1));
//   malicious.Add(nodes.Get(2));


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


  AnimationInterface anim ("wormhole.xml"); // Mandatory
//   AnimationInterface::SetConstantPosition (nodes.Get (0), 0, 0);
//   AnimationInterface::SetConstantPosition (nodes.Get (1), 80, 0);
//   AnimationInterface::SetConstantPosition (nodes.Get (2), 160, 0);
//   AnimationInterface::SetConstantPosition (nodes.Get (3), 240, 0);
//   AnimationInterface::SetConstantPosition (nodes.Get (4), 320, 0);
//   AnimationInterface::SetConstantPosition (nodes.Get (5), 400, 0);
//   AnimationInterface::SetConstantPosition (nodes.Get (6), 480, 0);
//   AnimationInterface::SetConstantPosition (nodes.Get (7), 560, 0);
//   AnimationInterface::SetConstantPosition (nodes.Get (8), 640, 0);
//   AnimationInterface::SetConstantPosition (nodes.Get (9), 720, 0);

  AnimationInterface::SetConstantPosition (nodes.Get (size - 1), 800, 0);
  
  anim.EnablePacketMetadata(true);

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

  // ★感度寄りに（拾いにくいならさらに下げる：-92〜-96あたり）
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

  // you can configure AODV attributes here using aodv.Set(name, value)
  InternetStackHelper stack;
  stack.SetRoutingHelper (aodv); // has effect on the next Install ()
  stack.Install (nodes);

  Ipv4AddressHelper address;
  address.SetBase ("10.0.0.0", "255.0.0.0","0.0.0.1");
  interfaces = address.Assign (devices);

  if (printRoutes)
    {
      Ptr<OutputStreamWrapper> routingStream = Create<OutputStreamWrapper> ("aodv.routes", std::ios::out);
      aodv.PrintRoutingTableAllAt (Seconds (8), routingStream);
    }
}

void
AodvExample::InstallApplications ()
{
  V4PingHelper ping (interfaces.GetAddress (size - 1));
  ping.SetAttribute ("Verbose", BooleanValue (true));

  ApplicationContainer p = ping.Install (nodes.Get (0));
  p.Start (Seconds (0));
  p.Stop (Seconds (totalTime) - Seconds (0.001));


}

