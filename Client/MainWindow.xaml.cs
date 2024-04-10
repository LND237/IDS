using Microsoft.Toolkit.Uwp.Notifications;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace Client
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            //Example of using communicator
            /*const int PORT_NUM = 50001, MAX_AMOUNT_PACKET = 1;
            int amount_packets = 0;
            Communicator communicator = new Communicator(PORT_NUM);
            communicator.StartListening();
            while (amount_packets < MAX_AMOUNT_PACKET)
            {
                try
                {
                    AttackData data = communicator.GetMessageServer();
                    amount_packets++;
                }
                catch(Exception excp) 
                {
                    string text = excp.Message;
                }
            }
            communicator.StopListening();*/
            /*IP ip = LocalAddress.GetLocalIP();
            MAC mac = LocalAddress.GetLocalMAC();*/
            
        }

        private void Settings_Image_MouseDown(object sender, MouseButtonEventArgs e)
        {
            Main.Content = new SettingsPage();
        }

        private void Attacks_Text_MouseDown(object sender, MouseButtonEventArgs e)
        {
            Main.Content = new AttacksPage();
        }

        private void FAQ_Image_MouseDown(object sender, MouseButtonEventArgs e)
        {
            Main.Content = new FAQ();
        }
    }
}