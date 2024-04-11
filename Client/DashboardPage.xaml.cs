using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
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
    /// Interaction logic for DashboardPage.xaml
    /// </summary>
    public partial class DashboardPage : Page
    {
        private static Object threadLock = new Object();
        public static bool abortMainDataThread = false;
        public DashboardPage()
        {
            InitializeComponent();
            if (!abortMainDataThread){
                Thread dataThread = new Thread(RefreshData);
                dataThread.Start();
                abortMainDataThread = true;
            }
        }
        private void RefreshData()
        {
            const int GAP_SECONDS = 3;
            while (true)
            {
                try
                {
                    // Simulate fetching data from database or any other source
                    MainWindow.attackLogs = MainWindow.GetDatabase().GetAttacksInLastNMinutes(MainWindow.LAST_DAY_AMOUNT_MINUTES);
                    MainWindow.InitAttackers();

                    // Update UI on the UI thread
                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        // Lock to ensure thread safety when updating shared data
                        lock (threadLock)
                        {
                            this.detailsItemsTopAttacks.ItemsSource = new List<AttackLog>(MainWindow.attackLogs);
                            this.detailsItemsAttackers.ItemsSource = new List<IP>(MainWindow.ipsAttackers);

                        }
                    });

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
