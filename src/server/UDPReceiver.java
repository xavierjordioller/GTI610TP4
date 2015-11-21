package server;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/**
 * Cette classe permet la reception d'un paquet UDP sur le port de reception
 * UDP/DNS. Elle analyse le paquet et extrait le hostname
 * 
 * Il s'agit d'un Thread qui ecoute en permanance pour ne pas affecter le
 * deroulement du programme
 * 
 * @author Max
 *
 */

public class UDPReceiver extends Thread {
	/**
	 * Les champs d'un Packet UDP 
	 * --------------------------
	 * En-tete (12 octects) 
	 * Question : l'adresse demande 
	 * Reponse : l'adresse IP
	 * Autorite :
	 * info sur le serveur d'autorite 
	 * Additionnel : information supplementaire
	 */

	/**
	 * Definition de l'En-tete d'un Packet UDP
	 * --------------------------------------- 
	 * Identifiant Parametres 
	 * QDcount
	 * Ancount
	 * NScount 
	 * ARcount
	 * 
	 * L'identifiant est un entier permettant d'identifier la requete. 
	 * parametres contient les champs suivant : 
	 * 		QR (1 bit) : indique si le message est une question (0) ou une reponse (1). 
	 * 		OPCODE (4 bits) : type de la requete (0000 pour une requete simple). 
	 * 		AA (1 bit) : le serveur qui a fourni la reponse a-t-il autorite sur le domaine? 
	 * 		TC (1 bit) : indique si le message est tronque.
	 *		RD (1 bit) : demande d'une requete recursive. 
	 * 		RA (1 bit) : indique que le serveur peut faire une demande recursive. 
	 *		UNUSED, AD, CD (1 bit chacun) : non utilises. 
	 * 		RCODE (4 bits) : code de retour.
	 *                       0 : OK, 1 : erreur sur le format de la requete,
	 *                       2: probleme du serveur, 3 : nom de domaine non trouve (valide seulement si AA), 
	 *                       4 : requete non supportee, 5 : le serveur refuse de repondre (raisons de sï¿½ecurite ou autres).
	 * QDCount : nombre de questions. 
	 * ANCount, NSCount, ARCount : nombre dï¿½entrees dans les champs ï¿½Reponseï¿½, Autorite,  Additionnel.
	 */

	protected final static int BUF_SIZE = 1024;
	protected String SERVER_DNS = null;//serveur de redirection (ip)
	protected int portRedirect = 53; // port  de redirection (par defaut)
	protected int port; // port de rï¿½ception
	private String adrIP = null; //bind ip d'ecoute
	private String DomainName = "none";
	private String DNSFile = null;
	private boolean RedirectionSeulement = false;
	private boolean found = false;
	private List<String> listAddr;
	UDPAnswerPacketCreator packetCreator;
	
	private class ClientInfo { //quick container
		public String client_ip = null;
		public int client_port = 0;
	};
	private HashMap<Integer, ClientInfo> Clients = new HashMap<>();
	
	private boolean stop = false;

	
	public UDPReceiver() {
		
	}
	

	public UDPReceiver(String SERVER_DNS, int Port) {
		this.SERVER_DNS = SERVER_DNS;
		this.port = Port;
	}
	
	
	private static byte[] IpStringToByte(String saddr) {
		String[] split = saddr.split("\\.");
		byte[] addr = new byte[4];
		int[] iaddr = new int[4];
		
		iaddr[0] = (int) Integer.valueOf(split[0]);
		iaddr[1] = (int) Integer.valueOf(split[1]);
		iaddr[2] = (int) Integer.valueOf(split[2]);
		iaddr[3] = (int) Integer.valueOf(split[3]);
		
		addr[0] = (byte) iaddr[0];
		addr[1] = (byte) iaddr[1];
		addr[2] = (byte) iaddr[2];
		addr[3] = (byte) iaddr[3];
		
		return addr;
	}
	
	public void setport(int p) {
		this.port = p;
	}

	public void setRedirectionSeulement(boolean b) {
		this.RedirectionSeulement = b;
	}

	public String gethostNameFromPacket() {
		return DomainName;
	}

	public String getAdrIP() {
		return adrIP;
	}

	private void setAdrIP(String ip) {
		adrIP = ip;
	}

	public String getSERVER_DNS() {
		return SERVER_DNS;
	}

	public void setSERVER_DNS(String server_dns) {
		this.SERVER_DNS = server_dns;
	}



	public void setDNSFile(String filename) {
		DNSFile = filename;
	}

	public void run() {
		try {
			DatagramSocket serveur = new DatagramSocket(this.port); // *Creation d'un socket UDP
		
			
			// *Boucle infinie de recpetion
			while (!this.stop) {
				byte[] buff = new byte[0xFF];
				DatagramPacket paquetRecu = new DatagramPacket(buff,buff.length);
				System.out.println("Serveur DNS  "+serveur.getLocalAddress()+"  en attente sur le port: "+ serveur.getLocalPort());

				// *Reception d'un paquet UDP via le socket
				serveur.receive(paquetRecu);
				
				System.out.println("paquet recu du  "+paquetRecu.getAddress()+"  du port: "+ paquetRecu.getPort());
				

				// *Creation d'un DataInputStream ou ByteArrayInputStream pour
				// manipuler les bytes du paquet

				ByteArrayInputStream TabInputStream = new ByteArrayInputStream (paquetRecu.getData());
				int size = TabInputStream.available();
				TabInputStream.read(buff, 0, size);
				
				String buff_bin = Integer.toBinaryString(buff[2]);
				
				boolean isRequest;
				if (buff_bin.length() == 8)
					isRequest = false;
				else 
					isRequest = true;
				
				
				// ****** Dans le cas d'un paquet requete *****
				if (isRequest) {
					// *Lecture du Query Domain name, a partir du 13 byte
					
					// Recherche du byte 0x06
					int start = 12;
					while(buff[start] != 0x06) {
						start++;
					}
					
					int i = 1;
					// Taille du QName
					int QNameSize = 0;
					while (buff[start + i] != 0x00) {
						QNameSize++;
						i++;
					}
					
					byte[] QName = new byte[QNameSize];
					
					i = 0;
					// Parcours de QNAME jusqu'a ce q'on trouve 0x02
					while (buff[start + 1 + i] != 0x00) {
						if (buff[start + 1 + i] == 0x02) {
							QName[i] = 0x2E;
						}
						else {
							//System.out.println(buff[12+i]);
							QName[i] = buff[start + 1 +i];								
						}
						i++;
					}

				
					
					// *Sauvegarde du Query Domain name				
					String QNameStr = new String(QName);
					System.out.println(QNameStr);
					
					// *Sauvegarde de l'adresse, du port et de l'identifiant de la requete
					InetAddress reqIP = paquetRecu.getAddress();
					int reqPort = paquetRecu.getPort();
					byte[] reqID = new byte[2];
					for (int j=0; j<2; j++) {
						reqID[j] = buff[j];
					}
					
					
					// *Si le mode est redirection seulement
					if(this.RedirectionSeulement) {
						// *Rediriger le paquet vers le serveur DNS
						//DatagramPacket paquetRedirige = new DatagramPacket(buff, buff.length);
						paquetRecu.setAddress(InetAddress.getByAddress(IpStringToByte(this.SERVER_DNS)));
						paquetRecu.setPort(50505);
						serveur.send(paquetRecu);		
					}
					// *Sinon
					else {
						// *Rechercher l'adresse IP associee au Query Domain name
						// dans le fichier de correspondance de ce serveur
						
						
						Path path = Paths.get(this.DNSFile);
						try {
							InputStream in = Files.newInputStream(path);
							BufferedReader  reader = new BufferedReader(new InputStreamReader(in));
							String line = "";
							while ((line = reader.readLine()) != null) {
								String[] domain = line.split(";");
								if (domain[0].equals(QNameStr)) {
									found = true;
									this.listAddr = new ArrayList<String>();
									for(int k = 1; k < domain.length; k++){
										listAddr.add(domain[k]);
									}
								}
							}
						} catch (IOException e) {
							e.printStackTrace();
						}
							
					}
						
					
					
					// *Si la correspondance n'est pas trouvee
					if (!found) {
						// *Rediriger le paquet vers le serveur DNS
						try {
							DatagramPacket paquetRedirige = new DatagramPacket(buff, buff.length);
							paquetRedirige.setAddress(InetAddress.getByAddress(IpStringToByte(this.SERVER_DNS)));
							paquetRedirige.setPort(50505);
							serveur.send(paquetRedirige);
						}
						catch (Exception e) {
							System.out.println("Not able to connect to further DNS Server");
						}
					}
					// *Sinon
					else {
						// *Creer le paquet de reponse a l'aide du UDPAnswerPaquetCreator
						// Creation du datagramme de reponse
						byte[] Qpacket = new byte[0xFF];
						
						// ID message DNS
						Qpacket[0] = reqID[0];
						Qpacket[1] = reqID[1];
						
						// QName
						Qpacket[12] = 0x06;
						int k;
						for(k = 1; k < QName.length; k++) {
							Qpacket[12+k] = QName[k];
						}
						Qpacket[12+k] = 0x00;

						packetCreator = packetCreator.getInstance();
						byte[] answerPacket = packetCreator.CreateAnswerPacket(Qpacket, listAddr);
						
						// *Placer ce paquet dans le socket
						DatagramPacket answerDatagramPacket = new DatagramPacket(answerPacket,answerPacket.length);
						answerDatagramPacket.setAddress(paquetRecu.getAddress());
						answerDatagramPacket.setPort(paquetRecu.getPort());
						
						// *Envoyer le paquet
						serveur.send(answerDatagramPacket);
						
					}
				}
				
				// ****** Dans le cas d'un paquet reponse *****
				else {
						// *Lecture du ANCOUNT
						byte[] b_ancount = new byte[2];
						b_ancount[0] = buff[6];
						b_ancount[1] = buff[7];
						
						ByteBuffer wrapped = ByteBuffer.wrap(b_ancount);
						short ancount = wrapped.getShort();
						
						
						// *Lecture du Query Domain name, a partir du 13 byte
						// Recherche du byte 0x06
						int start = 12;
						while(buff[start] != 0x06) {
							start++;
						}
						
						int i = 1;
						// Taille du QName
						int QNameSize = 0;
						while (buff[start + i] != 0x00) {
							QNameSize++;
							i++;
						}
						
						byte[] QName = new byte[QNameSize];
						
						i = 0;
						// Parcours de QName
						while (buff[start + 1 + i] != 0x00) {
							if (buff[start + 1 + i] == 0x02) {
								QName[i] = 0x2E;
							}
							else {
								//System.out.println(buff[12+i]);
								QName[i] = buff[start + 1 +i];								
							}
							i++;
						}
						
						String QNameStr = new String(QName);
						
						// *Passe par dessus Type et Class
						
						// *Passe par dessus les premiers champs du ressource record
						// pour arriver au ressource data qui contient l'adresse IP associe
						//  au hostname (dans le fond saut de 16 bytes)
						i = i + 16;
						
						// *Capture de ou des adresse(s) IP (ANCOUNT et le nombre
						// de réponses retournïées)			
						List<InetAddress> iplist = new ArrayList<InetAddress>();
						for(int k = 0; k < ancount; k++) {
							i = i + 1 + QNameSize + 1 + 9;
							byte[] b_rdlength = new byte[2];
							b_rdlength[0] = buff[i];
							b_rdlength[1] = buff[i+1];
							
							i = i+2;
							
							ByteBuffer wrappedRD = ByteBuffer.wrap(b_rdlength);
							short rdlength = wrapped.getShort();
							if (rdlength == 4) {
								byte[] ip = new byte[4];
								ip[0] = buff[i];
								ip[1] = buff[i+1];
								ip[2] = buff[i+2];
								ip[3] = buff[i+3];
								iplist.add(InetAddress.getByAddress(ip));
							}
							i = i + rdlength;
							System.out.printf("ancountRD = %d",ancount);
						}
						
						// *Ajouter la ou les correspondance(s) dans le fichier DNS
						// si elles ne y sont pas deja
						Path path = Paths.get(this.DNSFile);

						try {
							InputStream in = Files.newInputStream(path);
							BufferedReader  reader = new BufferedReader(new InputStreamReader(in));
							String line = "";
							
							OutputStream out = Files.newOutputStream(path);
							BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(out));
							
							boolean found = false;
							
							while ((line = reader.readLine()) != null) {
								String[] domain = line.split(";");
								if (domain[0].equals(QNameStr)) {
									found = true;
									for(int j = 1; j < domain.length; j++) {
										int ind;
										if((ind = iplist.indexOf(domain[j])) != -1) {
											line = line + ";" + iplist.get(ind).getHostAddress();
										}
									}
								}
								writer.write(line);
							}
							if (!found) {
								String new_line = QNameStr + ";";
								for (int j = 0; j < iplist.size(); j++) {
									new_line = new_line + iplist.get(j).getHostAddress();
								}
								writer.write(new_line);
							}
						} catch (IOException e) {
							e.printStackTrace();
						}
						
						
						// *Faire parvenir le paquet reponse au demandeur original,
						// ayant emis une requete avec cet identifiant				
						// *Placer ce paquet dans le socket
						// *Envoyer le paquet
						serveur.send(paquetRecu);
				}
			}
			serveur.close(); //closing server
		} catch (Exception e) {
			System.err.println("Problï¿½me ï¿½ l'exï¿½cution :");
			e.printStackTrace(System.err);
		}
	}
}
