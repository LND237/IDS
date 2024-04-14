using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
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
    /// Interaction logic for SettingsPage.xaml
    /// </summary>
    public partial class SettingsPage : Page
    {
        private static readonly int PORT_NUM = 50001;
        public static  bool NotificationEnabled { get; set; }
        public static Communicator communicator = new Communicator(PORT_NUM);
        public SettingsPage()
        {
            InitializeComponent();
        }
        private void Toggle2_Checked(object sender, RoutedEventArgs e)
        {
            NotificationEnabled = true;
            communicator.StartListening();

        }

        private void Toggle2_Unchecked(object sender, RoutedEventArgs e)
        {
            communicator.StopListening();
            NotificationEnabled = false;
        }

        private void Toggle1_Checked(object sender, RoutedEventArgs e)
        {
            AppTheme.ChangeTheme(new Uri("Themes/Light.xaml", UriKind.Relative));

        }

        private void Toggle1_Unchecked(object sender, RoutedEventArgs e)
        {
            AppTheme.ChangeTheme(new Uri("Themes/Dark.xaml", UriKind.Relative));
        }
    }
}
