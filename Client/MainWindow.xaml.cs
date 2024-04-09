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