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
using MaterialDesignThemes.Wpf;
using Microsoft.Toolkit.Uwp.Notifications;
using Windows.ApplicationModel.Activation;

namespace Client
{

    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public static readonly int LAST_DAY_AMOUNT_MINUTES = 1440;
        private static List<AttackLog> attackLogs;
        private static List<IP> ipsAttackers;
        private static bool areThreadsActive = false;
        private static Object threadLock = new Object();
        public MainWindow()
        {
            InitializeComponent();
            //Activating threads just in the beginning
            if (!areThreadsActive)
            {
                Thread threadData = new Thread(RefreshData);
                threadData.Start();
                Thread threadMessages = new Thread(GetMessages);
                threadMessages.Start();
                areThreadsActive = true;
            }

        }
        private void Image_MouseDown(object sender, MouseButtonEventArgs e)
        {
            Main.Content = new DashboardPage();
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
                        AttackData attack = SettingsPage.communicator.GetMessageServer();
                        // Requires Microsoft.Toolkit.Uwp.Notifications NuGet package version 7.0 or greater
                        new ToastContentBuilder()
                           
                            .AddArgument("conversationId", 9813)
                            .AddText("You were attacked from " + attack.GetIP() + "in " + attack.GetName())
                            .AddText("Check this out!")
                            .Show(); // Not seeing the Show() method? Make sure you have version 7.0, and if you're using .NET 6 (or later), then your TFM must be net6.0-windows10.0.17763.0 or greater

                        Thread.Sleep(10000);
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
            MainWindow.ipsAttackers = ipsAttackers;
        }

        public static MongoDBAttackLogger GetDatabase()
        {
            const string DATABASE_NAME = "IDE_DB";
            string username = EnvFile.GetVariable("USERNAME_DB"), password = EnvFile.GetVariable("PASSWORD_DB");
            MongoDBAttackLogger database = new MongoDBAttackLogger(username, password, DATABASE_NAME, LocalAddress.GetLocalMAC());
            return database;
        }

        private void RefreshData()
        {
            const int GAP_SECONDS = 3;
            while (true)
            {
                MainWindow.attackLogs = GetDatabase().GetAttacksInLastNMinutes(LAST_DAY_AMOUNT_MINUTES);
                InitAttackers();
                lock (threadLock)
                {
                    this.detailsItemsTopAttacks.ItemsSource = attackLogs;
                    this.detailsItemsAttackers.ItemsSource = ipsAttackers;
                }

                Thread.Sleep(GAP_SECONDS * 100);
            }
        }
    }
}