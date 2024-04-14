using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
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
        public static List<AttackLog> attackLogs;
        public static List<IP> ipsAttackers;
        public static bool areThreadsActive = false;
        private static Object threadLock = new Object();
        public MainWindow()
        {
            InitializeComponent();
            //Activating threads just in the beginning
            Thread dataThread = new Thread(RefreshData);
            dataThread.Start();
            Thread threadMessages = new Thread(GetMessages);
            threadMessages.Start();
            areThreadsActive = true;    
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


        public void GetMessages()
        {
            while (true)
            {
                if (SettingsPage.NotificationEnabled)
                {
                    try
                    {
                        AttackData attack = SettingsPage.communicator.GetMessageServer();

                        if (SettingsPage.NotificationEnabled)
                        {
                            new ToastContentBuilder()
                                .AddArgument("conversationId", 9813)
                            .AddText("Pronet-You were attacked!!")
                            .AddText("There was a " + attack.GetName() + " from " + attack.GetIP())
                            .AddText("You should check it on the app.")
                            .Show();
                        }
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
            Main.Content = new DashboardPage();
        }

        public static void InitAttackers()
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

        public void RefreshData()
        {
            const int GAP_SECONDS = 3;
            while (true)
            {
                try
                {
                    // Simulate fetching data from database or any other source
                    MainWindow.attackLogs = GetDatabase().GetAttacksInLastNMinutes(LAST_DAY_AMOUNT_MINUTES);
                    InitAttackers();

                    // Update UI on the UI thread
                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        // Lock to ensure thread safety when updating shared data
                        lock (threadLock)
                        {
                            this.detailsItemsTopAttacks.ItemsSource = new List<AttackLog>(attackLogs);
                            this.detailsItemsAttackers.ItemsSource = new List<IP>(ipsAttackers);

                        }
                    });
                    if (DashboardPage.abortMainDataThread){
                        break;
                    }
                    // Wait for a couple of seconds before fetching data again
                    Task.Delay(TimeSpan.FromSeconds(GAP_SECONDS));
                }
                catch (Exception ex)
                {
                    // Handle exception appropriately
                    MessageBox.Show(ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);                   
                }
            }
        }
    }
}