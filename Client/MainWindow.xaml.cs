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
using Microsoft.Toolkit.Uwp.Notifications;

namespace Client
{

    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public static readonly int LAST_DAY_AMOUNT_MINUTES = 1440;
        private List<AttackLog> attackLogs;
        private List<IP> ipsAttackers;
        public MainWindow()
        {
            InitializeComponent();
            this.attackLogs = GetDatabase().GetAttacksInLastNMinutes(LAST_DAY_AMOUNT_MINUTES * 30);
            InitAttackers();
            this.detailsItemsTopAttacks.ItemsSource = attackLogs;
            this.detailsItemsAttackers.ItemsSource = ipsAttackers;
            //Example of using communicator
            //const int PORT_NUM = 50001, MAX_AMOUNT_PACKET = 1;
            //int amount_packets = 0;
            //Communicator communicator = new Communicator(PORT_NUM);
            //communicator.StartListening();
            //while (amount_packets < MAX_AMOUNT_PACKET)
            //{
            //    try
            //    {
            //        AttackData data = communicator.GetMessageServer();
            //        amount_packets++;
            //    }
            //    catch (Exception excp)
            //    {
            //        string text = excp.Message;
            //    }
            //}
            //communicator.StopListening();
            //IP ip = LocalAddress.GetLocalIP();
            //MAC mac = LocalAddress.GetLocalMAC();

            //Thread thread = new Thread(GetMessages);
            //thread.Start();
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

        private void Visualization_Image_MouseDown(object sender, MouseButtonEventArgs e)
        {
            Main.Content = new VisualizationPage();
        }

        private void GetMessages()
        {
            while (true)
            {
                if (SettingsPage.NotificationEnabled)
                {
                    try
                    {
                        //AttackData attack = SettingsPage.communicator.GetMessageServer();
                        // Requires Microsoft.Toolkit.Uwp.Notifications NuGet package version 7.0 or greater
                        new ToastContentBuilder()
                            .AddArgument("action", "viewConversation")
                            .AddArgument("conversationId", 9813)
                            .AddText("Andrew sent you a picture")
                            .AddText("Check this out, The Enchantments in Washington!")
                            .Show(); // Not seeing the Show() method? Make sure you have version 7.0, and if you're using .NET 6 (or later), then your TFM must be net6.0-windows10.0.17763.0 or greater
                    }
                    catch
                    {

                    }

                }
            }
        }

        private void Home_Image_MouseDown(object sender, MouseButtonEventArgs e)
        {
            InitializeComponent();
        }

        private void InitAttackers()
        {
            const int MAX_AMOUNT_IPS = 5;
            MongoDBAttackLogger database = MainWindow.GetDatabase();
            List<IP> ipsAttackers = database.GetAllAttackerIps();
            if(ipsAttackers.Count > MAX_AMOUNT_IPS)
            {
                ipsAttackers = ipsAttackers.Slice(0, MAX_AMOUNT_IPS);
            }
            this.ipsAttackers = ipsAttackers;
        }

        public static MongoDBAttackLogger GetDatabase()
        {
            const string DATABASE_NAME = "IDE_DB";
            string username = EnvFile.GetVariable("USERNAME_DB"), password = EnvFile.GetVariable("PASSWORD_DB");
            MongoDBAttackLogger database = new MongoDBAttackLogger(username, password, DATABASE_NAME, LocalAddress.GetLocalMAC());
            return database;
        }
    }
}