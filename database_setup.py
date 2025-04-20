from app import app, db
from models import User, RestaurantTable

with app.app_context():
    db.create_all()
    print("База данных создана!")

    if not User.query.filter_by(username="admin").first():
        admin = User(username="admin")
        admin.set_password("password")
        db.session.add(admin)

    if not RestaurantTable.query.first():
        tables = [
            RestaurantTable(table_number=1, capacity=2),
            RestaurantTable(table_number=2, capacity=4),
            RestaurantTable(table_number=3, capacity=6),
        ]
        db.session.add_all(tables)

    db.session.commit()
    print("Данные добавлены в базу!")
