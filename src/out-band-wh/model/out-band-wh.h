#ifndef OUT_BAND_WH_H
#define OUT_BAND_WH_H

#include "ns3/application.h"
#include "ns3/net-device.h"
#include "ns3/ipv4-address.h"
#include "ns3/socket.h"
#include "ns3/tag.h"   // ★ WhTag 用
#include "ns3/uinteger.h"  // ★ 追加（h側でも属性を使うなら入れてOK）

namespace ns3
{

// ==============================
// Wormhole 用のパケットタグ
// ==============================
class WhTag : public Tag
{
public:
  WhTag() {}

  static TypeId GetTypeId (void);
  virtual TypeId GetInstanceTypeId (void) const override;

  // 今回は中身を持たないので空でOK
  virtual uint32_t GetSerializedSize (void) const override
  {
    return 0;
  }

  virtual void Serialize (TagBuffer i) const override
  {
    // 何も書かない
  }

  virtual void Deserialize (TagBuffer i) override
  {
    // 何も読まない
  }

  virtual void Print (std::ostream &os) const override
  {
    os << "WhTag";
  }
};

// ==============================
// 外部 WH アプリケーション本体
// ==============================
class WormholeApp : public Application
{
public:
  static TypeId GetTypeId (void);

  WormholeApp ();
  virtual ~WormholeApp ();

  void Setup(Ptr<NetDevice> dev, Ipv4Address peer, uint16_t port);

private:
  virtual void StartApplication() override;
  virtual void StopApplication() override;

  // ★ 戻り値 bool （ループ防止のため WH パケットを判定してスキップ）
  bool PromiscSniff(Ptr<NetDevice> dev,
                    Ptr<const Packet> pkt,
                    uint16_t protocol,
                    const Address& src,
                    const Address& dst,
                    NetDevice::PacketType type);

  void TunnelRecv(Ptr<Socket> socket);

  Ptr<NetDevice> m_dev;   // sniff / 再送する無線デバイス
  Ptr<Socket>    m_socket; // WH トンネル用 UDP ソケット
  Ipv4Address    m_peer;   // 相方 WH ノードの P2P IP
  uint16_t       m_port;   // WH トンネル用 UDP ポート

  // ★追加：転送モード
  // 0: 全て転送
  // 1: RREQ/RREPのみ(Hello除外)
  uint8_t m_forwardMode {0};
};


class WhTunnelHeader : public Header
{
public:
  static TypeId GetTypeId (void);
  TypeId GetInstanceTypeId (void) const override;

  void Set (uint16_t etherType,
            uint8_t  packetType,
            Mac48Address src,
            Mac48Address dst,
            Ipv4Address ipSrc,
            Ipv4Address ipDst);

  uint16_t GetEtherType () const { return m_etherType; }
  uint8_t  GetPacketType() const { return m_packetType; }
  Mac48Address GetSrcMac () const { return m_src; }
  Mac48Address GetDstMac () const { return m_dst; }
  Ipv4Address GetIpSrc () const { return m_ipSrc; }
  Ipv4Address GetIpDst () const { return m_ipDst; }

  // Header interface
  uint32_t GetSerializedSize (void) const override;
  void Serialize (Buffer::Iterator i) const override;
  uint32_t Deserialize (Buffer::Iterator i) override;
  void Print (std::ostream &os) const override;

private:
  uint16_t m_etherType {0};     // 0x0800 など
  uint8_t  m_packetType {0};    // NetDevice::PacketType
  Mac48Address m_src;
  Mac48Address m_dst;
  Ipv4Address m_ipSrc;
  Ipv4Address m_ipDst;
};

} // namespace ns3

#endif // OUT_BAND_WH_H
