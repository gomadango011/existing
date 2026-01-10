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

using namespace ns3;

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
  test.Report (std::cout);
  return 0;
}

//-----------------------------------------------------------------------------
AodvExample::AodvExample () :
  size (7),
  size_a (5),
  step (50),
  totalTime (100),
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
  Simulator::Destroy ();
}

void
AodvExample::Report (std::ostream &)
{ 
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
                                "X", StringValue("ns3::UniformRandomVariable[Min=0|Max=300]"),
                                "Y", StringValue("ns3::UniformRandomVariable[Min=-100|Max=100]")
                                );
  
  mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");

  mobility.Install(nodes);

  for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        //攻撃者ノード以外にAODVをインストール
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


     AnimationInterface anim ("wormhole.xml"); // Mandatory
  AnimationInterface::SetConstantPosition (nodes.Get (0), 0, 0);
  AnimationInterface::SetConstantPosition (nodes.Get (1), 100, 0);//WH1
  AnimationInterface::SetConstantPosition (nodes.Get (2), 200, 0);//WH2
  AnimationInterface::SetConstantPosition (nodes.Get (3), 250, 0);
  AnimationInterface::SetConstantPosition (nodes.Get (4), 50, 0);
  AnimationInterface::SetConstantPosition (nodes.Get (5), 275, 20);
  AnimationInterface::SetConstantPosition (nodes.Get (size - 1), 300, 0);
  
  anim.EnablePacketMetadata(true);

}

void
AodvExample::CreateDevices ()
{
  WifiMacHelper wifiMac;
  wifiMac.SetType ("ns3::AdhocWifiMac");
  YansWifiPhyHelper wifiPhy = YansWifiPhyHelper::Default ();
  YansWifiChannelHelper wifiChannel = YansWifiChannelHelper::Default ();
  wifiPhy.SetChannel (wifiChannel.Create ());
  WifiHelper wifi;
  wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager", "DataMode", StringValue ("OfdmRate6Mbps"), "RtsCtsThreshold", UintegerValue (0));
  devices = wifi.Install (wifiPhy, wifiMac, nodes); 

  PointToPointHelper pointToPoint;
  pointToPoint.SetDeviceAttribute ("DataRate", StringValue ("5Mbps"));
  pointToPoint.SetChannelAttribute ("Delay", StringValue ("2ms"));

  // NetDeviceContainer devices;
  mal_devices = pointToPoint.Install (malicious);

  if (pcap)
    {
      wifiPhy.EnablePcapAll (std::string ("aodv"));
      pointToPoint.EnablePcapAll (std::string ("point-to-point"));
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
  stack.Install (not_malicious);

  InternetStackHelper stack2;
  stack2.Install(malicious);
  //IDstack2.Install (malicious);
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
  V4PingHelper ping (interfaces.GetAddress (size - 1));
  ping.SetAttribute ("Verbose", BooleanValue (true));

  ApplicationContainer p = ping.Install (nodes.Get (0));
  p.Start (Seconds (0));
  p.Stop (Seconds (totalTime) - Seconds (0.001));

  // ---- 外部 WH アプリケーションの設定 ----
    // node1: ENTRY 側（wifi をスニファして、node2 の p2p IP にトンネル送信）
    {
        Ptr<WormholeApp> whEntry = CreateObject<WormholeApp>();
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

