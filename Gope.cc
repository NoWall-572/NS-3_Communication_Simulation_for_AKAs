/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
// THIS IS THE SECOND BASELINE SIMULATION CODE
// This code implements the AKA protocol from the paper:
// "A provably secure authentication scheme for RFID-enabled UAV applications"
// by P. Gope, O. Millwood, and N. Saxena (DOI: 10.1016/j.comcom.2020.11.009)
// The network environment is kept identical to OurScheme.cc for fair comparison.

#include "ns3/ptr.h"
#include "ns3/packet.h"
#include "ns3/header.h"
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/applications-module.h"
#include "ns3/wifi-module.h"
#include "ns3/mobility-module.h"
#include "ns3/internet-module.h"
#include "ns3/netanim-module.h"
#include "ns3/olsr-helper.h" // For MANET routing
#include "math.h"
#include <map>
#include <iomanip> // For std::fixed and std::setprecision

// --- Communication Cost (Gope et al., Estimated from protocol) ---
#define BASELINE2_PSI1_SIZE 48
#define BASELINE2_PSI2_SIZE 64
#define BASELINE2_PSI3_SIZE 80

#define NUAV 20         // Edit this!!!
#define ENDTIME 1500

// --- Computational Cost (Gope et al., Table 2 & 3) ---
#define BASELINE2_SERVER_COMP_DELAY 0.045 // Server prepares M2 (1 hash)
#define BASELINE2_TAG_COMP_DELAY    14.58 // Tag prepares M3 (total tag cost)
#define BASELINE2_SERVER_FINAL_COMP_DELAY 3.46 // Server verifies M3 (FE.Rec)

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("UAV_AKA_Baseline_Gope_Simulation");

Ipv4InterfaceContainer uavInterfaces;
uint16_t uavCommPort = 23456;

//----------------------------------------------------------------
//--MyHeader: 
//----------------------------------------------------------------
class MyHeader : public Header
{
public:
  MyHeader () : m_data(0) {}
  virtual ~MyHeader () {}
  void SetData (uint16_t msgType, uint16_t sourceId, uint16_t targetId) {
    m_data = msgType * 10000 + sourceId * 100 + targetId;
  }
  uint16_t GetMsgType() { return m_data / 10000; }
  uint16_t GetSourceId() { return (m_data % 10000) / 100; }
  uint16_t GetTargetId() { return m_data % 100; }
  static TypeId GetTypeId (void) {
    static TypeId tid = TypeId ("ns3::MyHeader").SetParent<Header>().AddConstructor<MyHeader>();
    return tid;
  }
  virtual TypeId GetInstanceTypeId (void) const { return GetTypeId (); }
  virtual uint32_t GetSerializedSize (void) const { return 2; }
  virtual void Serialize (Buffer::Iterator start) const { start.WriteHtonU16 (m_data); }
  virtual uint32_t Deserialize (Buffer::Iterator start) { m_data = start.ReadNtohU16 (); return 2; }
  virtual void Print (std::ostream &os) const { os << "data=" << m_data; }
private:
  uint16_t m_data;
};

//----------------------------------------------------------------------
//-- TimestampTag: 
//----------------------------------------------------------------------
class TimestampTag : public Tag {
public:
  static TypeId GetTypeId (void) {
    static TypeId tid = TypeId ("TimestampTag").SetParent<Tag> ().AddConstructor<TimestampTag> ();
    return tid;
  }
  virtual TypeId GetInstanceTypeId (void) const { return GetTypeId (); }
  virtual uint32_t GetSerializedSize (void) const { return 8; }
  virtual void Serialize (TagBuffer i) const { int64_t t = m_timestamp.GetNanoSeconds (); i.Write ((const uint8_t *)&t, 8); }
  virtual void Deserialize (TagBuffer i) { int64_t t; i.Read ((uint8_t *)&t, 8); m_timestamp = NanoSeconds (t); }
  void SetTimestamp (Time time) { m_timestamp = time; }
  Time GetTimestamp (void) const { return m_timestamp; }
  void Print (std::ostream &os) const { os << "t=" << m_timestamp; }
private:
  Time m_timestamp;
};


//----------------------------------------------------------------------
//-- UAVApp: Implements the 3-way handshake protocol from Gope et al.
//----------------------------------------------------------------------
class UAVApp : public Application
{
public:
  UAVApp ();
  virtual ~UAVApp ();

  void Setup (Ptr<Socket> socket, DataRate dataRate, Ptr<UniformRandomVariable> rand);
  void InitCryptoParameters(uint16_t id);

  uint32_t GetAuthAttempts() { return m_auth_attempts; }
  uint32_t GetAuthSuccess() { return m_auth_success; }
  Time GetTotalAuthDelay() { return m_total_auth_delay; }
  uint32_t GetPacketsSent() { return m_packets_sent; }
  uint32_t GetPacketsReceived() { return m_packets_received; }
  Time GetTotalCommDelay() { return m_total_comm_delay; }

  uint64_t GetTotalBytesReceived() { return m_bytes_received; }

private:
  virtual void StartApplication (void);
  virtual void StopApplication (void);
  void ScheduleNextAuth();
  void StartAuthentication();
  
  void SendM1 (uint16_t targetId);
  void HandleM1_SendM2 (Ptr<Packet> packet, uint16_t sourceId);
  void HandleM2_SendM3 (Ptr<Packet> packet, uint16_t sourceId);
  void HandleM3_Finalize (Ptr<Packet> packet, uint16_t sourceId);

  void SocketRecv (Ptr<Socket> socket);

  void DoSendM1();
  void DoSendM2(uint16_t targetId);
  void DoSendM3(uint16_t targetId);
  
  void FinalizeInitiatorSuccess();

  Ptr<Socket>     m_socket;
  bool            m_running;
  uint16_t        m_id;
  
  uint16_t        m_session_target_id;
  bool            m_is_authenticating;
  
  uint32_t        m_auth_attempts, m_auth_success;
  Time            m_total_auth_delay, m_auth_start_time;

  uint32_t        m_packets_sent, m_packets_received;
  Time            m_total_comm_delay;
  

  uint64_t        m_bytes_received;

  Ptr<UniformRandomVariable> m_rand;
};

UAVApp::UAVApp () : m_socket(0), m_running(false), m_id(0),
                    m_is_authenticating(false), m_auth_attempts(0), 
                    m_auth_success(0), m_total_auth_delay(Seconds(0)),
                    m_packets_sent(0), m_packets_received(0), m_total_comm_delay(Seconds(0)),
                    m_bytes_received(0) {} 

UAVApp::~UAVApp() {}

void UAVApp::Setup (Ptr<Socket> socket, DataRate dataRate, Ptr<UniformRandomVariable> rand)
{
  m_socket = socket;
  m_rand = rand;
}

void UAVApp::InitCryptoParameters(uint16_t id) { m_id = id; }

void UAVApp::StartApplication() {
    m_running = true;
    m_socket->SetRecvCallback (MakeCallback (&UAVApp::SocketRecv, this));
    Simulator::Schedule(Seconds(m_rand->GetValue(1.0, 5.0)), &UAVApp::ScheduleNextAuth, this);
}

void UAVApp::StopApplication() {
    m_running = false;
    if (m_socket) {
        m_socket->Close();
        m_socket = 0;
    }
}

void UAVApp::ScheduleNextAuth()
{
    if (!m_running || m_is_authenticating) return;
    double nextAuthTime = m_rand->GetValue(5.0, 10.0);
    Simulator::Schedule(Seconds(nextAuthTime), &UAVApp::StartAuthentication, this);
}

void UAVApp::StartAuthentication()
{
    if (!m_running || m_is_authenticating) return;
    uint16_t targetId;
    do {
        targetId = m_rand->GetInteger(0, NUAV - 1);
    } while (targetId == m_id);

    m_is_authenticating = true;
    m_session_target_id = targetId;
    m_auth_start_time = Simulator::Now();
    m_auth_attempts++;

    NS_LOG_INFO("Time " << Simulator::Now().GetSeconds() << "s: UAV " << m_id << " ---> starts Gope AKA with UAV " << targetId);
    SendM1(targetId);
}

void UAVApp::SendM1 (uint16_t targetId)
{
  DoSendM1();
}

void UAVApp::DoSendM1()
{
  Ptr<Packet> packet = Create<Packet> (BASELINE2_PSI1_SIZE);
  MyHeader header;
  header.SetData(1, m_id, m_session_target_id);
  packet->AddHeader (header);
  
  TimestampTag timestamp;
  timestamp.SetTimestamp(Simulator::Now());
  packet->AddPacketTag(timestamp);

  Ipv4Address targetAddress = uavInterfaces.GetAddress(m_session_target_id, 0);
  InetSocketAddress remoteAddr = InetSocketAddress(targetAddress, uavCommPort);
  m_socket->SendTo(packet, 0, remoteAddr);
  m_packets_sent++;
  
  NS_LOG_INFO("Time " << Simulator::Now().GetSeconds() << "s: UAV " << m_id << " --M1--> sends to UAV " << m_session_target_id);
}


void UAVApp::SocketRecv (Ptr<Socket> socket)
{
  Address from;
  Ptr<Packet> packet = socket->RecvFrom (from);
  if (!packet) return;

  m_bytes_received += packet->GetSize();

  m_packets_received++;
  TimestampTag timestamp;
  if (packet->RemovePacketTag(timestamp)) {
      m_total_comm_delay += (Simulator::Now() - timestamp.GetTimestamp());
  }

  MyHeader header;
  packet->RemoveHeader (header);
  
  switch (header.GetMsgType()) {
    case 1: HandleM1_SendM2(packet, header.GetSourceId()); break;
    case 2: HandleM2_SendM3(packet, header.GetSourceId()); break;
    case 3: HandleM3_Finalize(packet, header.GetSourceId()); break;
    default: break;
  }
}

void UAVApp::HandleM1_SendM2 (Ptr<Packet> packet, uint16_t sourceId)
{
    NS_LOG_INFO("Time " << Simulator::Now().GetSeconds() << "s: UAV " << m_id << " <--M1-- received from UAV " << sourceId);
    Simulator::Schedule(MilliSeconds(BASELINE2_SERVER_COMP_DELAY), &UAVApp::DoSendM2, this, sourceId);
}

void UAVApp::DoSendM2(uint16_t targetId)
{
    Ptr<Packet> packet = Create<Packet> (BASELINE2_PSI2_SIZE);
    MyHeader header;
    header.SetData(2, m_id, targetId);
    packet->AddHeader(header);
    
    TimestampTag timestamp;
    timestamp.SetTimestamp(Simulator::Now());
    packet->AddPacketTag(timestamp);
    
    Ipv4Address targetAddress = uavInterfaces.GetAddress(targetId, 0);
    InetSocketAddress remoteAddr = InetSocketAddress(targetAddress, uavCommPort);
    m_socket->SendTo(packet, 0, remoteAddr);
    m_packets_sent++;
    
    NS_LOG_INFO("Time " << Simulator::Now().GetSeconds() << "s: UAV " << m_id << " --M2--> sends back to UAV " << targetId);
}

void UAVApp::HandleM2_SendM3 (Ptr<Packet> packet, uint16_t sourceId)
{
    NS_LOG_INFO("Time " << Simulator::Now().GetSeconds() << "s: UAV " << m_id << " <--M2-- received from UAV " << sourceId);

    if (!m_is_authenticating || sourceId != m_session_target_id) {
        NS_LOG_WARN("Received unexpected M2 from " << sourceId);
        return;
    }
    
    Simulator::Schedule(MilliSeconds(BASELINE2_TAG_COMP_DELAY), &UAVApp::FinalizeInitiatorSuccess, this);
}

void UAVApp::DoSendM3(uint16_t targetId)
{
    Ptr<Packet> packet = Create<Packet> (BASELINE2_PSI3_SIZE);
    MyHeader header;
    header.SetData(3, m_id, targetId);
    packet->AddHeader(header);
    
    TimestampTag timestamp;
    timestamp.SetTimestamp(Simulator::Now());
    packet->AddPacketTag(timestamp);
    
    Ipv4Address targetAddress = uavInterfaces.GetAddress(targetId, 0);
    InetSocketAddress remoteAddr = InetSocketAddress(targetAddress, uavCommPort);
    m_socket->SendTo(packet, 0, remoteAddr);
    m_packets_sent++;

    NS_LOG_INFO("Time " << Simulator::Now().GetSeconds() << "s: UAV " << m_id << " --M3--> sends to UAV " << targetId);
}

void UAVApp::HandleM3_Finalize (Ptr<Packet> packet, uint16_t sourceId)
{
    NS_LOG_INFO("Time " << Simulator::Now().GetSeconds() << "s: UAV " << m_id << " <--M3-- received from UAV " << sourceId);
    Simulator::Schedule(MilliSeconds(BASELINE2_SERVER_FINAL_COMP_DELAY), [] () {
        NS_LOG_INFO("Gope AKA complete for responder.");
    });
}

void UAVApp::FinalizeInitiatorSuccess()
{
    m_auth_success++;
    Time delay = (Simulator::Now() - m_auth_start_time) + MilliSeconds(BASELINE2_TAG_COMP_DELAY);
    m_total_auth_delay += delay;
    NS_LOG_UNCOND("Time " << Simulator::Now().GetSeconds() << "s: UAV " << m_id << " <---> GOPE AKA SUCCESS with UAV " << m_session_target_id << ". Total Delay: " << delay.GetMilliSeconds() << " ms");   
    // After computation is 'done', send M3
    DoSendM3(m_session_target_id);

    m_is_authenticating = false;
    m_session_target_id = 0;
    ScheduleNextAuth();
}

int main (int argc, char *argv[])
{
  std::string phyMode ("DsssRate2Mbps");
  CommandLine cmd;
  cmd.AddValue ("phyMode", "Wifi Phy mode", phyMode);
  cmd.Parse (argc,argv);

  Config::SetDefault ("ns3::WifiRemoteStationManager::FragmentationThreshold", StringValue ("2200"));
  Config::SetDefault ("ns3::WifiRemoteStationManager::RtsCtsThreshold", StringValue ("2200"));
  Config::SetDefault ("ns3::WifiRemoteStationManager::NonUnicastMode", StringValue (phyMode));

  NodeContainer uavNodes;
  uavNodes.Create (NUAV);

  YansWifiChannelHelper wifiChannel;
  wifiChannel.AddPropagationLoss ("ns3::LogDistancePropagationLossModel","Exponent", DoubleValue(3.67) ,"ReferenceLoss", DoubleValue(8), "ReferenceDistance", DoubleValue(1.0));
  wifiChannel.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
  YansWifiPhyHelper wifiPhy = YansWifiPhyHelper::Default ();
  wifiPhy.SetChannel (wifiChannel.Create ());
  wifiPhy.SetErrorRateModel ("ns3::YansErrorRateModel");
  wifiPhy.Set ("TxPowerStart", DoubleValue (20.0));
  wifiPhy.Set ("TxPowerEnd", DoubleValue (20.0));
  wifiPhy.Set ("TxGain", DoubleValue (3.0));
  wifiPhy.Set ("RxGain", DoubleValue (3.0));
  wifiPhy.Set ("RxNoiseFigure", DoubleValue (7));

  WifiHelper wifi;
  wifi.SetStandard (WIFI_PHY_STANDARD_80211b);
  wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager", "DataMode",StringValue (phyMode), "ControlMode",StringValue (phyMode));
  NqosWifiMacHelper wifiMac = NqosWifiMacHelper::Default();
  wifiMac.SetType ("ns3::AdhocWifiMac");
  NetDeviceContainer uavDevices = wifi.Install (wifiPhy, wifiMac, uavNodes);

  MobilityHelper mobility;
  mobility.SetPositionAllocator ("ns3::GridPositionAllocator",
                                 "MinX", DoubleValue (-500.0), "MinY", DoubleValue (-500.0),
                                 "DeltaX", DoubleValue (80.0), "DeltaY", DoubleValue (80.0),
                                 "GridWidth", UintegerValue (5), "LayoutType", StringValue ("RowFirst"));
  mobility.SetMobilityModel ("ns3::RandomWalk2dMobilityModel",
                             "Bounds", RectangleValue (Rectangle (-1000, 1000, -1000, 1000)),
                             "Mode", StringValue ("Time"), "Time", StringValue ("2s"),
                             "Speed", StringValue ("ns3::ConstantRandomVariable[Constant=10]"));
  mobility.Install (uavNodes);

  OlsrHelper olsr;
  InternetStackHelper stack;
  stack.SetRoutingHelper (olsr);
  stack.Install (uavNodes);
  Ipv4AddressHelper address;
  address.SetBase ("192.168.1.0", "255.255.255.0");
  uavInterfaces = address.Assign (uavDevices);
  
  TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
  Ptr<UAVApp> uavApps[NUAV];
  
  Ptr<UniformRandomVariable> randVar = CreateObject<UniformRandomVariable> ();

  for(uint16_t i = 0; i < NUAV; i++) {
      Ptr<Socket> socket = Socket::CreateSocket (uavNodes.Get(i), tid);
      InetSocketAddress localAddr = InetSocketAddress (Ipv4Address::GetAny(), uavCommPort);
      socket->Bind (localAddr);
      uavApps[i] = CreateObject<UAVApp> ();
      uavApps[i]->Setup(socket, DataRate("2Mbps"), randVar);
      uavApps[i]->InitCryptoParameters(i);
      uavNodes.Get(i)->AddApplication(uavApps[i]);
      uavApps[i]->SetStartTime(Seconds(1.0));
      uavApps[i]->SetStopTime(Seconds(ENDTIME));
  }

  AnimationInterface anim ("uav-aka-baseline-gope-animation.xml");
  for (uint32_t j = 0; j < NUAV; ++j) {
      std::ostringstream nodeDesc;
      nodeDesc << "UAV-" << j;
      anim.UpdateNodeDescription (uavNodes.Get(j), nodeDesc.str());
      anim.UpdateNodeColor (uavNodes.Get(j), 0, 255, 0); // Set baseline to green
  }
  
  Simulator::Stop (Seconds (ENDTIME+2));
  NS_LOG_UNCOND("Starting simulation for Baseline (Gope et al.) for " << ENDTIME << " seconds...");
  Simulator::Run ();
  NS_LOG_UNCOND("Simulation finished.");

  uint32_t totalAuthAttempts = 0, totalAuthSuccess = 0;
  Time totalAuthDelay = Time(0);
  uint32_t totalPacketsSent = 0, totalPacketsReceived = 0;
  Time totalCommDelay = Time(0);
  uint64_t totalBytesReceived = 0;

  for(uint16_t i = 0; i < NUAV; i++) {
    totalAuthAttempts += uavApps[i]->GetAuthAttempts();
    totalAuthSuccess += uavApps[i]->GetAuthSuccess();
    totalAuthDelay += uavApps[i]->GetTotalAuthDelay();
    totalPacketsSent += uavApps[i]->GetPacketsSent();
    totalPacketsReceived += uavApps[i]->GetPacketsReceived();
    totalCommDelay += uavApps[i]->GetTotalCommDelay();
    totalBytesReceived += uavApps[i]->GetTotalBytesReceived();
  }
  
  std::cout << "\n----------------------------------------------------" << std::endl;
  std::cout << "---      Simulation Final Results (Baseline 2)   ---" << std::endl;
  std::cout << "----------------------------------------------------" << std::endl;

  std::cout << std::fixed << std::setprecision(5);

  std::cout << "\n--- Application Layer Performance ---" << std::endl;
  std::cout << "Total Authentication Attempts: " << totalAuthAttempts << std::endl;
  std::cout << "Total Successful Authentications: " << totalAuthSuccess << std::endl;

  if (totalAuthAttempts > 0) {
    double authSuccessRate = static_cast<double>(totalAuthSuccess) / static_cast<double>(totalAuthAttempts) * 100.0;
    std::cout << "Authentication Success Rate: " << authSuccessRate << "%" << std::endl;
  }
  if (totalAuthSuccess > 0) {
    double avgAuthDelay = (totalAuthDelay.GetSeconds() * 1000.0) / static_cast<double>(totalAuthSuccess);
    std::cout << "Average Authentication Delay (initiator's perspective): " << avgAuthDelay << " ms" << std::endl;
  }

  std::cout << "\n--- Network Layer Performance ---" << std::endl;
  std::cout << "Total Packets Sent: " << totalPacketsSent << std::endl;
  std::cout << "Total Packets Received: " << totalPacketsReceived << std::endl;

  if (totalPacketsSent > 0) {
      double packetLoss = totalPacketsSent - totalPacketsReceived;
      double lossRate = (packetLoss / static_cast<double>(totalPacketsSent)) * 100.0;
      std::cout << "Packet Loss Rate: " << lossRate << "%" << std::endl;
  }
  if (totalPacketsReceived > 0) {
      double avgCommDelay = (totalCommDelay.GetSeconds() * 1000.0) / static_cast<double>(totalPacketsReceived);
      std::cout << "Average Communication Delay (per packet): " << avgCommDelay << " ms" << std::endl;
  }
  
  // Throughput Calculation and Output
  std::cout << "\n--- Aggregate Network Throughput ---" << std::endl;
  if (ENDTIME > 0 && totalBytesReceived > 0)
    {
      double throughput_bps = (static_cast<double>(totalBytesReceived) * 8.0) / ENDTIME;
      if (throughput_bps > 1000000.0)
        {
          std::cout << "Average Throughput: " << throughput_bps / 1000000.0 << " Mbps" << std::endl;
        }
      else if (throughput_bps > 1000.0)
        {
          std::cout << "Average Throughput: " << throughput_bps / 1000.0 << " kbps" << std::endl;
        }
      else
        {
          std::cout << "Average Throughput: " << throughput_bps << " bps" << std::endl;
        }
    }
  else
    {
      std::cout << "Average Throughput: 0 bps" << std::endl;
    }

  Simulator::Destroy ();
  return 0;
}
