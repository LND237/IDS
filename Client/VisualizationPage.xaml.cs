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
using System.Collections.Generic;
using static MaterialDesignThemes.Wpf.Theme.ToolBar;
using System.Runtime.InteropServices;
using System.Reflection.PortableExecutable;

namespace Client
{
    /// <summary>
    /// Interaction logic for Visualization.xaml
    /// </summary>
    public partial class VisualizationPage : Page
    {
        private static readonly Dictionary<string, string> ATTACKS_COLORS = new Dictionary<string, string>()
        {
            {"DDOS", "#9FCDFF" }, {"DNS", "#984FFF"}, {"Drive By Download", "#666B70"}, {"Smurf", "#1DDD92"}, {"XSS", "#189FD1"}
        };
        private List<Category> categories { get; set; }
        private List<Column> columns { get; set; }
        public VisualizationPage()
        {
            const int PIE_WIDTH = 150, PIE_HEIGHT = 150;
            InitializeComponent();
            this.InitPageData();

            #region test #data
            //categories = [new Category(59, "DDOS", new SolidColorBrush((Color)ColorConverter.ConvertFromString(ATTACKS_COLORS["DDOS"]))),
            //new Category(10, "DNS", new SolidColorBrush((Color)ColorConverter.ConvertFromString(ATTACKS_COLORS["DNS"]))),
            //new Category(10, "Category 3", new SolidColorBrush((Color)ColorConverter.ConvertFromString("#666B70"))),
            //new Category(10, "Category 4", new SolidColorBrush((Color)ColorConverter.ConvertFromString("#1DDD92"))),
            //new Category(11, "Category 5", new SolidColorBrush((Color)ColorConverter.ConvertFromString("#189FD1")))];
            //columns = [new Column("XSS", 7, new SolidColorBrush((Color)ColorConverter.ConvertFromString(ATTACKS_COLORS["XSS"]))),
            //    new Column("DBD", 16, new SolidColorBrush((Color)ColorConverter.ConvertFromString(ATTACKS_COLORS["Drive By Download"])))];
            #endregion

            detailsItemsControlPie.ItemsSource = categories;
            detailsItemsControlColumn.ItemsSource = columns;

            DrawPie(categories, PIE_WIDTH, PIE_HEIGHT);
        }

        private void InitPageData()
        {
            //Extracting attack's data from database
            const string DATABASE_NAME = "IDE_DB";
            string username = EnvFile.GetVariable("USERNAME_DB"), password = EnvFile.GetVariable("PASSWORD_DB");
            MongoDBAttackLogger database = new MongoDBAttackLogger(username, password, DATABASE_NAME, LocalAddress.GetLocalMAC());
            List<MongoDBAttackLogger.AttackLog> attacks = database.getAllAttacks();

            this.categories = new List<Category>();
            this.columns = new List<Column>();

            //Creating counting dictionary for attacks
            Dictionary<string, int> attackCounter = new Dictionary<string, int>();
            foreach(string key in ATTACKS_COLORS.Keys)
            {
                attackCounter.Add(key, 0);
            }
            
            //Getting amount of each attack
            foreach(MongoDBAttackLogger.AttackLog attack in attacks) 
            {
                attackCounter[attack.AttackName] += 1;
            }

            //Going over the amounts
            foreach (var (attackName, amountAttack) in attackCounter) 
            {
                int precentageAttack = (int)((float)amountAttack * 100 / attacks.Count);
                Brush colorAttack = new SolidColorBrush((Color)ColorConverter.ConvertFromString(ATTACKS_COLORS[attackName]));
                string nameOfAttack = attackName;
                if(attackName.Equals("Drive By Download"))
                {
                    nameOfAttack = "DBD";
                }
                this.categories.Add(new Category(precentageAttack, nameOfAttack, colorAttack));
                this.columns.Add(new Column(nameOfAttack, amountAttack, colorAttack));
            }
        }

        /// <summary>
        /// The function draws the pie chart according to the data
        /// of the categories.
        /// </summary>
        /// <param name="categories">The categories with the data.</param>
        private void DrawPie(List<Category> categories, int pieWidth, int pieHeight)
        {
            const int HALF_FULL_PRECENTAGE = 50;
            float centerX = pieWidth / 2, centerY = pieHeight / 2, radius = pieWidth / 2;
            pieCanvas.Width = pieWidth;
            pieCanvas.Height = pieHeight;
            // draw pie
            float angle = 0, prevAngle = 0;
            foreach (Category category in categories)
            {
                //Calculating lines
                double line1X = (radius * Math.Cos(angle * Math.PI / 180)) + centerX;
                double line1Y = (radius * Math.Sin(angle * Math.PI / 180)) + centerY;

                angle = category.GetPrecentage() * (float)360 / 100 + prevAngle;

                double arcX = (radius * Math.Cos(angle * Math.PI / 180)) + centerX;
                double arcY = (radius * Math.Sin(angle * Math.PI / 180)) + centerY;

                //Making lines segments
                LineSegment line1Segment = new LineSegment(new Point(line1X, line1Y), false);
                double arcWidth = radius, arcHeight = radius;
                bool isLargeArc = category.GetPrecentage() > HALF_FULL_PRECENTAGE;
                ArcSegment arcSegment = new ArcSegment()
                {
                    Size = new Size(arcWidth, arcHeight),
                    Point = new Point(arcX, arcY),
                    SweepDirection = SweepDirection.Clockwise,
                    IsLargeArc = isLargeArc,
                };
                LineSegment line2Segment = new LineSegment(new Point(centerX, centerY), false);

                //Building path figure
                PathFigure pathFigure = new PathFigure(new Point(centerX, centerY),
                new List<PathSegment>()
                {
                line1Segment,
                arcSegment,
                line2Segment,
                }, true);

                List<PathFigure> pathFigures = new List<PathFigure>() { pathFigure, };
                PathGeometry pathGeometry = new PathGeometry(pathFigures);
                Path path = new Path()
                {
                    Fill = category.GetColorBrush(),
                    Data = pathGeometry,
                };
                pieCanvas.Children.Add(path);

                prevAngle = angle;

                // Drawing outlines
                Line outline1 = new Line()
                {
                    X1 = centerX,
                    Y1 = centerY,
                    X2 = line1Segment.Point.X,
                    Y2 = line1Segment.Point.Y,
                    Stroke = Brushes.White,
                    StrokeThickness = 1,
                };
                Line outline2 = new Line()
                {
                    X1 = centerX,
                    Y1 = centerY,
                    X2 = arcSegment.Point.X,
                    Y2 = arcSegment.Point.Y,
                    Stroke = Brushes.White,
                    StrokeThickness = 1,
                };

                pieCanvas.Children.Add(outline1);
                pieCanvas.Children.Add(outline2);
            }
        }
    }
}